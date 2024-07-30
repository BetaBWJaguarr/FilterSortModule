from flask import request, jsonify
from functools import wraps

from authentication.shared import users_collection, sessions

ROLE_PERMISSIONS = {
    "admin": {"admin_api_use", "user_api_use"},
    "user": {"user_api_use"},
}

def has_permission(role, permission):
    return permission in ROLE_PERMISSIONS.get(role, set())

def permission_required(permission):
    from authentication.auth import login_required
    def decorator(f):
        @wraps(f)
        @login_required
        def wrapper(*args, **kwargs):
            session_id = request.headers.get('Authorization')
            user_session = sessions.get(session_id)
            user = users_collection.find_one({"_id": user_session['user_id']})
            if not user or not has_permission(user.get('role'), permission):
                return jsonify({"error": "Permission denied"}), 403

            return f(*args, **kwargs)
        return wrapper
    return decorator
