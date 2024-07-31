import uuid
from werkzeug.security import generate_password_hash, check_password_hash

class User:
    def __init__(self, username, email, password, role='user',security_question=None, security_answer=None):
        self.id = str(uuid.uuid4())
        self.username = username
        self.email = email
        self.password = generate_password_hash(password)
        self.role = role
        self.is_verified = False
        self.security_question = security_question
        self.security_answer = generate_password_hash(security_answer)  # Hashing the answer

    def to_dict(self):
        return {
            "_id": self.id,
            "username": self.username,
            "email": self.email,
            "password": self.password,
            "role": self.role,
            "is_verified": self.is_verified,
            "security_question": self.security_question,
            "security_answer": self.security_answer,
            "constent": True
        }

