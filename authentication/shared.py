from pymongo import MongoClient, errors
import configparser

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
