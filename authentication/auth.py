from flask import request, jsonify, Blueprint
from pymongo import MongoClient, errors
import uuid
import configparser
import scrypt
from werkzeug.security import check_password_hash, generate_password_hash

from app import limiter
from authentication.emailmanager.emailmanager import send_email
from authentication.tokenmanager.tokenmanager import verify_token, generate_token
from users.userobjects import User
from functools import wraps
from datetime import datetime, timedelta

config = configparser.ConfigParser()
config.read('config.ini')

try:
    client = MongoClient(config.get('database', 'connection_string'))
    db = client[config.get('database', 'db_name')]
    users_collection = db['users']
except errors.PyMongoError as e:
    print(f"Database connection error: {e}")
    raise SystemExit("Database connection failed. Please check your configuration.")

sessions = {}
failed_login_attempts = {}
lockout_time = timedelta(minutes=15)

auth = Blueprint('auth', __name__)

SESSION_TIMEOUT = timedelta(hours=92)
LOGIN_ATTEMPT_LIMIT = 5
LOGIN_ATTEMPT_WINDOW = timedelta(minutes=10)

def hash_password(password):
    salt = uuid.uuid4().bytes
    return salt, scrypt.hash(password, salt)

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        session_id = request.headers.get('Authorization')
        if not session_id or session_id not in sessions:
            return jsonify({"error": "Unauthorized"}), 401

        session_data = sessions.get(session_id)
        last_active = session_data['last_active']

        if datetime.utcnow() - last_active > SESSION_TIMEOUT:
            sessions.pop(session_id, None)
            return jsonify({"error": "Session expired"}), 401

        session_data['last_active'] = datetime.utcnow()
        return f(*args, **kwargs)
    return wrapper

@auth.route('/filtermanager/auth/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        if not username or not email or not password:
            return jsonify({"error": "Missing required fields"}), 400

        if users_collection.find_one({"email": email}):
            return jsonify({"error": "User already exists"}), 400

        user = User(username, email, password)
        users_collection.insert_one(user.to_dict())

        token = generate_token({'user_id': user.id}, expiration_minutes=60)
        verification_link = f"http://yourdomain.com/verify/{token}"
        send_email("Verify your email", email, f"Click here to verify your email: {verification_link}")

        return jsonify({"message": "User registered successfully", "user_id": user.id}), 201
    except errors.PyMongoError as e:
        return jsonify({"error": "Database error. Please try again later."}), 500

@auth.route('/filtermanager/auth/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        if email in failed_login_attempts:
            failed_attempt = failed_login_attempts[email]
            if failed_attempt['count'] >= LOGIN_ATTEMPT_LIMIT and datetime.utcnow() - failed_attempt['last_failed_attempt'] < LOGIN_ATTEMPT_WINDOW:
                return jsonify({"error": "Account locked. Please try again later."}), 403

        user_data = users_collection.find_one({"email": email})

        if user_data:
            if check_password_hash(user_data['password'], password):
                session_id = next((k for k, v in sessions.items() if v['user_id'] == user_data['_id']), None) or str(uuid.uuid4())
                sessions[session_id] = {'user_id': user_data['_id'], 'last_active': datetime.utcnow()}
                if email in failed_login_attempts:
                    del failed_login_attempts[email]
                return jsonify({"message": "Login successful", "session_id": session_id}), 200


        if email in failed_login_attempts:
            failed_login_attempts[email]['count'] += 1
        else:
            failed_login_attempts[email] = {'count': 1, 'last_failed_attempt': datetime.utcnow()}

        failed_login_attempts[email]['last_failed_attempt'] = datetime.utcnow()

        if failed_login_attempts[email]['count'] >= LOGIN_ATTEMPT_LIMIT:
            return jsonify({"error": "Account locked. Please try again later."}), 403

        return jsonify({"error": "Invalid email or password"}), 401
    except errors.PyMongoError as e:
        return jsonify({"error": "Database error. Please try again later."}), 500

@auth.route('/filtermanager/auth/logout', methods=['POST'])
@limiter.limit("5 per minute")
@login_required
def logout():
    try:
        session_id = request.headers.get('Authorization')
        sessions.pop(session_id, None)
        return jsonify({"message": "Logout successful"}), 200
    except errors.PyMongoError as e:
        return jsonify({"error": "Database error. Please try again later."}), 500

@auth.route('/filtermanager/auth/reset_password', methods=['POST'])
@limiter.limit("5 per minute")
def reset_password():
    try:
        data = request.get_json()
        user_data = users_collection.find_one({"email": data.get('email')})

        if user_data and check_password_hash(user_data['password_hash'], data.get('old_password')):
            users_collection.update_one({"email": data.get('email')}, {"$set": {"password_hash": generate_password_hash(data.get('new_password'))}})
            return jsonify({"message": "Password reset successful"}), 200

        return jsonify({"error": "Invalid email or password"}), 401
    except errors.PyMongoError as e:
        return jsonify({"error": "Database error. Please try again later."}), 500

@auth.route('/filtermanager/auth/update_info', methods=['PUT'])
@limiter.limit("5 per minute")
@login_required
def update_info():
    try:
        data = request.get_json()
        session_id = request.headers.get('Authorization')
        user_id = sessions[session_id]['user_id']

        updated_data = {}
        if 'username' in data:
            updated_data['username'] = data['username']
        if 'email' in data:
            updated_data['email'] = data['email']
        if 'password' in data:
            salt, updated_data['password'] = hash_password(data['password'])

        users_collection.update_one({"_id": user_id}, {"$set": updated_data})
        return jsonify({"message": "User info updated successfully"}), 200
    except errors.PyMongoError as e:
        return jsonify({"error": "Database error. Please try again later."}), 500

@auth.route('/filtermanager/auth/delete_account', methods=['DELETE'])
@limiter.limit("5 per minute")
@login_required
def delete_account():
    try:
        session_id = request.headers.get('Authorization')
        user_id = sessions[session_id]['user_id']

        users_collection.delete_one({"_id": user_id})
        sessions.pop(session_id, None)
        return jsonify({"message": "User account deleted successfully"}), 200
    except errors.PyMongoError as e:
        return jsonify({"error": "Database error. Please try again later."}), 500

#Backend Auth Manager
@auth.route('/filtermanager/auth/verify/<token>', methods=['GET'])
def verify_email(token):
    data = verify_token(token)
    if data:
        user_id = data.get('user_id')
        if users_collection.find_one({"_id": user_id}):
            # Update user verification status here
            return jsonify({"message": "Email verified successfully"}), 200
        return jsonify({"error": "Invalid user"}), 400
    return jsonify({"error": "Invalid or expired token"}), 400
