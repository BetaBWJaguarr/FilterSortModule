import uuid
from datetime import datetime
from flask import request
from pymongo import MongoClient, errors
import configparser

config = configparser.ConfigParser()
config.read('config.ini')

try:
    client = MongoClient(config.get('database', 'connection_string'))
    db = client[config.get('database', 'db_name')]
    users_collection = db['users']
    admin_logs = db['admin_logs']
except errors.PyMongoError as e:
    print(f"Database connection error: {e}")
    raise SystemExit("Database connection failed. Please check your configuration.")

def log_admin_activity(action, details="", status="success", metadata=None):
    try:
        action_id = str(uuid.uuid4())

        ip_address = request.remote_addr or "Unknown IP"
        user_agent = request.headers.get('User-Agent', 'Unknown User-Agent')
        method = request.method
        endpoint = request.path

        log_entry = {
            "action_id": action_id,
            "action": action,
            "timestamp": datetime.utcnow(),
            "details": details,
            "status": status,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "method": method,
            "endpoint": endpoint,
            "execution_time": None,
            "metadata": metadata or {}
        }

        admin_logs.insert_one(log_entry)
        return action_id
    except errors.PyMongoError as e:
        print(f"Error logging admin activity: {e}")
        return None


sessions = {}
failed_login_attempts = {}
