import jwt
import datetime
from flask import current_app

def generate_token(data, expiration_minutes=30):
    try:
        expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=expiration_minutes)

        secret_key = current_app.config.get('SECRET_KEY')
        if not secret_key:
            raise ValueError("SECRET_KEY is not set in Flask config")

        token = jwt.encode({'exp': expiration, **data}, secret_key, algorithm='HS256')

        return token if isinstance(token, str) else token.decode('utf-8')
    except Exception as e:
        print(f"Error generating token: {e}")
        return None

def verify_token(token):
    try:
        secret_key = current_app.config.get('SECRET_KEY')
        if not secret_key:
            raise ValueError("SECRET_KEY is not set in Flask config")

        decoded = jwt.decode(token, secret_key, algorithms=['HS256'])
        return decoded
    except jwt.ExpiredSignatureError:
        print("Token expired")
        return None
    except jwt.InvalidTokenError:
        print("Invalid token")
        return None
