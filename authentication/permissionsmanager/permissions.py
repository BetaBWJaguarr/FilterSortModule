from flask import request, jsonify
from functools import wraps
from authentication.shared import sessions, users_collection

ROLE_PERMISSIONS = {
    "admin": {"admin_api_use", "user_api_use"},
    "user": {"user_api_use"},
}

def has_permission(role, permission):
    return permission in ROLE_PERMISSIONS.get(role, set())

def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            session_id = request.headers.get('Authorization')

            if not session_id:
                return jsonify({"error": "Unauthorized"}), 401

            user_session = sessions.get(session_id)
            if not user_session:
                return jsonify({"error": "Unauthorized"}), 401

            user = users_collection.find_one({"_id": user_session['user_id']})
            if not user or not has_permission(user.get('role'), permission):
                return jsonify({"error": "Permission denied"}), 403

            return f(*args, **kwargs)
        return wrapper
    return decorator
