from flask import request, jsonify, Blueprint
from pymongo import MongoClient
import uuid
import configparser
from werkzeug.security import generate_password_hash, check_password_hash
from users.userobjects import User
from errorhandling.errormanager import CustomValueError, CustomTypeError, CustomIndexError, CustomKeyError, CustomFileNotFoundError
from filtermanager.managers.manager import match_request, sort_request, multi_filter_request
from anonymizer.dataanonymizer import Anonymizer
from functools import wraps

# Load configuration from config.ini
config = configparser.ConfigParser()
config.read('config.ini')

connection_string = config.get('database', 'connection_string')
db_name = config.get('database', 'db_name')

# MongoDB setup
client = MongoClient(connection_string)
db = client[db_name]
users_collection = db['users']
sessions = {}

app = Blueprint('restapi', __name__)

@app.route('/filtermanager/register', methods=['POST'])
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

@app.route('/filtermanager/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user_data = users_collection.find_one({"email": email})
    if user_data and check_password_hash(user_data['password_hash'], password):
        session_id = str(uuid.uuid4())
        sessions[session_id] = user_data['_id']
        return jsonify({"message": "Login successful", "session_id": session_id}), 200

    return jsonify({"error": "Invalid email or password"}), 401

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        session_id = request.headers.get('Authorization')
        if not session_id or session_id not in sessions:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper

@app.route('/filtermanager/match', methods=['POST'])
@login_required
def match():
    try:
        data = request.get_json()
        connection_string = data.get('connection_string')
        db_name = data.get('db_name')
        collection_name = data.get('collection_name')
        filter_data = data.get('match')

        page = request.args.get('page', type=int)
        items_per_page = request.args.get('items_per_page', type=int)

        valid_keys = {'connection_string', 'db_name', 'collection_name', 'match'}
        if not set(data.keys()).issubset(valid_keys):
            invalid_keys = set(data.keys()) - valid_keys
            raise CustomValueError(f"Invalid keys: {', '.join(invalid_keys)}. Valid keys are: {', '.join(valid_keys)}.")

        results = match_request(data, filter_data, page, items_per_page)

        anonymizer = Anonymizer(connection_string, db_name, collection_name)
        for index, document in enumerate(results):
            try:
                anonymized_fields = anonymizer.anonymize_sensitive_fields(document)
                if anonymized_fields:
                    results[index] = {**document, **anonymized_fields}
            except CustomValueError as e:
                results[index] = {"error": str(e)}

        return jsonify(results)

    except (CustomValueError, CustomTypeError, CustomIndexError, CustomKeyError, CustomFileNotFoundError) as e:
        return jsonify({"error": str(e), "details": e.details}), 400

    except Exception as e:
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500

@app.route('/filtermanager/sort', methods=['POST'])
@login_required
def sort():
    try:
        data = request.get_json()
        filter_data = data.get('filter', {})
        sort_data = data.get('sort', None)
        compare_field = data.get('compare_field', None)

        valid_keys = {'db_name', 'collection_name', 'connection_string', 'filter', 'sort', 'compare_field'}
        if not set(data.keys()).issubset(valid_keys):
            invalid_keys = set(data.keys()) - valid_keys
            raise CustomValueError(f"Invalid keys: {', '.join(invalid_keys)}. Valid keys are: {', '.join(valid_keys)}.")

        results = sort_request(data, filter_data, sort_data, compare_field)
        anonymizer = Anonymizer(connection_string, db_name, collection_name)

        for index, document in enumerate(results):
            try:
                anonymized_fields = anonymizer.anonymize_sensitive_fields(document)
                if anonymized_fields:
                    results[index] = {**document, **anonymized_fields}
            except CustomValueError as e:
                results[index] = {"error": str(e)}

        return jsonify(results)

    except (CustomValueError, CustomTypeError, CustomIndexError, CustomKeyError, CustomFileNotFoundError) as e:
        return jsonify({"error": str(e), "details": e.details, "traceback": e.traceback}), 400
    except Exception as e:
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500

@app.route('/filtermanager/multi_filter', methods=['POST'])
@login_required
def multi_filter():
    try:
        data = request.get_json()
        filters = data.get('filters', [])
        sort_data = data.get('sort_data', None)
        limit = data.get('limit', None)
        skip = data.get('skip', None)
        unwind_field = data.get('unwind_field', None)
        group_by = data.get('group_by', None)
        projection = data.get('projection', None)
        facet_fields = data.get('facet_fields', None)

        valid_keys = {'db_name', 'collection_name', 'connection_string', 'filters', 'sort_data', 'limit', 'skip', 'unwind_field', 'group_by', 'projection', 'facet_fields'}
        if not set(data.keys()).issubset(valid_keys):
            invalid_keys = set(data.keys()) - valid_keys
            raise CustomValueError(f"Invalid keys: {', '.join(invalid_keys)}. Valid keys are: {', '.join(valid_keys)}.")

        results = multi_filter_request(data, filters, sort_data, limit, skip, unwind_field, group_by, projection, facet_fields)
        anonymizer = Anonymizer(connection_string, db_name, collection_name)

        for index, document in enumerate(results):
            try:
                anonymized_fields = anonymizer.anonymize_sensitive_fields(document)
                if anonymized_fields:
                    results[index] = {**document, **anonymized_fields}
            except CustomValueError as e:
                results[index] = {"error": str(e)}

        return jsonify(results)

    except (CustomValueError, CustomTypeError, CustomIndexError, CustomKeyError, CustomFileNotFoundError) as e:
        return jsonify({"error": str(e), "details": e.details, "traceback": e.traceback}), 400
    except Exception as e:
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500