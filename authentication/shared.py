import uuid
from datetime import datetime

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

def log_admin_activity(action, details=""):
    try:
        action_id = str(uuid.uuid4())
        admin_logs.insert_one({
            "action_id": action_id,
            "action": action,
            "timestamp": datetime.utcnow(),
            "details": details
        })
        return action_id
    except errors.PyMongoError as e:
        print(f"Error logging admin activity: {e}")
        return None


sessions = {}
failed_login_attempts = {}
