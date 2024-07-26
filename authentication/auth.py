import random
import string
from flask import request, jsonify, Blueprint
from flask_limiter import Limiter
from pymongo import MongoClient, errors
import uuid
import configparser
from werkzeug.security import check_password_hash, generate_password_hash
from authentication.emailmanager.emailmanager import send_email
from authentication.permissionsmanager.permissions import permission_required
from authentication.tokenmanager.tokenmanager import verify_token, generate_token
from users.userobjects import User
from functools import wraps
from datetime import datetime, timedelta


from authentication.shared import sessions, users_collection, failed_login_attempts

SESSION_TIMEOUT = timedelta(hours=92)
LOGIN_ATTEMPT_LIMIT = 5
LOGIN_ATTEMPT_WINDOW = timedelta(minutes=10)
lockout_time = timedelta(minutes=15)

auth = Blueprint('auth', __name__)

limiter = Limiter(key_func=lambda: request.remote_addr)

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
        role = 'user'

        if not username or not email or not password:
            return jsonify({"error": "Missing required fields"}), 400

        if users_collection.find_one({"email": email}):
            return jsonify({"error": "User already exists"}), 400

        user = User(username, email, password, role=role)
        users_collection.insert_one(user.to_dict())

        token = generate_token({'user_id': user.id}, expiration_minutes=60)
        verification_link = f"http://127.0.0.1:5000/filtermanager/auth/verify/{token}"
        send_email("Verify your email", email, f"Click here to verify your email: {verification_link}")

        return jsonify({"message": "User registered successfully", "user_id": user.id}), 201
    except errors.PyMongoError as e:
        return jsonify({"error": "Database error. Please try again later."}), 500

@auth.route('/filtermanager/auth/login', methods=['POST'])
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
            if not user_data.get('is_verified'):
                return jsonify({"error": "Email not verified. Please verify your email before logging in."}), 401

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
@permission_required('user_api_use')
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
@permission_required('user_api_use')
def reset_password():
    try:
        data = request.get_json()
        email = data.get('email')

        user_data = users_collection.find_one({"email": email})

        if user_data:
            token = generate_token({'email': email}, expiration_minutes=15)
            reset_link = f"http://127.0.0.1:5000/filtermanager/auth/update_password/{token}"
            send_email("Reset your password", email, f"Click here to reset your password: {reset_link}")
            return jsonify({"message": "Password reset email sent"}), 200

        return jsonify({"error": "Email not found"}), 404
    except errors.PyMongoError as e:
        return jsonify({"error": "Database error. Please try again later."}), 500

@auth.route('/filtermanager/auth/update_info', methods=['PUT'])
@limiter.limit("5 per minute")
@permission_required('user_api_use')
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
            updated_data['password'] = generate_password_hash(data['password'])

        users_collection.update_one({"_id": user_id}, {"$set": updated_data})
        return jsonify({"message": "User info updated successfully"}), 200
    except errors.PyMongoError as e:
        return jsonify({"error": "Database error. Please try again later."}), 500

@auth.route('/filtermanager/auth/delete_account', methods=['DELETE'])
@limiter.limit("5 per minute")
@permission_required('user_api_use')
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
        user = users_collection.find_one({"_id": user_id})

        if user:
            if user.get('is_verified'):
                return jsonify({"message": "User is already verified"}), 200

            users_collection.update_one({"_id": user_id}, {"$set": {"is_verified": True}})

            return jsonify({"message": "Email verified successfully"}), 200

        return jsonify({"error": "Invalid user"}), 400

    return jsonify({"error": "Invalid or expired token"}), 400

def generate_default_password():
    length = 12
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

@auth.route('/filtermanager/auth/update_password/<token>', methods=['GET'])
def update_password(token):
    data = verify_token(token)
    if data:
        email = data.get('email')

        default_password = generate_default_password()
        hashed_password = generate_password_hash(default_password)

        if email:
            users_collection.update_one({"email": email}, {"$set": {"password": hashed_password}})
            return jsonify({
                "message": "Password reseted successfully",
                "default_password": default_password
            }), 200

        return jsonify({"error": "Missing email"}), 400
    return jsonify({"error": "Invalid or expired token"}), 400
