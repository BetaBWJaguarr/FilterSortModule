from flask import request, jsonify, Blueprint
from pymongo import MongoClient
import uuid
import configparser
import scrypt
from werkzeug.security import check_password_hash, generate_password_hash
from users.userobjects import User
from functools import wraps
from datetime import datetime, timedelta

config = configparser.ConfigParser()
config.read('config.ini')

client = MongoClient(config.get('database', 'connection_string'))
db = client[config.get('database', 'db_name')]
users_collection = db['users']
sessions = {}

auth = Blueprint('auth', __name__)

SESSION_TIMEOUT = timedelta(hours=92)

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
def register():
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
    return jsonify({"message": "User registered successfully", "user_id": user.id}), 201

@auth.route('/filtermanager/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    user_data = users_collection.find_one({"email": data.get('email')})

    if user_data and check_password_hash(user_data['password'], data.get('password')):
        session_id = next((k for k, v in sessions.items() if v['user_id'] == user_data['_id']), None) or str(uuid.uuid4())
        sessions[session_id] = {'user_id': user_data['_id'], 'last_active': datetime.utcnow()}
        return jsonify({"message": "Login successful", "session_id": session_id}), 200

    return jsonify({"error": "Invalid email or password"}), 401

@auth.route('/filtermanager/auth/logout', methods=['POST'])
@login_required
def logout():
    session_id = request.headers.get('Authorization')
    sessions.pop(session_id, None)
    return jsonify({"message": "Logout successful"}), 200

@auth.route('/filtermanager/auth/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    user_data = users_collection.find_one({"email": data.get('email')})

    if user_data and check_password_hash(user_data['password_hash'], data.get('old_password')):
        users_collection.update_one({"email": data.get('email')}, {"$set": {"password_hash": generate_password_hash(data.get('new_password'))}})
        return jsonify({"message": "Password reset successful"}), 200

    return jsonify({"error": "Invalid email or password"}), 401


@auth.route('/filtermanager/auth/update_info', methods=['PUT'])
@login_required
def update_info():
    data = request.get_json()
    session_id = request.headers.get('Authorization')
    user_id = sessions[session_id]['user_id']

    updated_data = {}
    if 'username' in data:
        updated_data['username'] = data['username']
    if 'email' in data:
        updated_data['email'] = data['email']
    if 'password' in data:
        salt, updated_data['password_hash'] = hash_password(data['password'])

    users_collection.update_one({"_id": user_id}, {"$set": updated_data})
    return jsonify({"message": "User info updated successfully"}), 200

@auth.route('/filtermanager/auth/delete_account', methods=['DELETE'])
@login_required
def delete_account():
    session_id = request.headers.get('Authorization')
    user_id = sessions[session_id]['user_id']

    users_collection.delete_one({"_id": user_id})
    sessions.pop(session_id, None)
    return jsonify({"message": "User account deleted successfully"}), 200
