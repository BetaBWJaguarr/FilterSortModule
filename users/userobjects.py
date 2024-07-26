import uuid
from werkzeug.security import generate_password_hash, check_password_hash

class User:
    def __init__(self, username, email, password, role='user'):
        self.id = str(uuid.uuid4())
        self.username = username
        self.email = email
        self.password = generate_password_hash(password)
        self.role = role
        self.is_verified = False

    def to_dict(self):
        return {
            "_id": self.id,
            "username": self.username,
            "email": self.email,
            "password": self.password,
            "role": self.role,
            "is_verified": self.is_verified,
        }

