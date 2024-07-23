import jwt
import datetime
from flask import current_app

def generate_token(data, expiration_minutes=30):
    try:
        expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=expiration_minutes)
        token = jwt.encode({'exp': expiration, **data}, current_app.config['SECRET_KEY'], algorithm='HS256')
        return token
    except Exception as e:
        print(f"Error generating token: {e}")
        return None

def verify_token(token):
    try:
        decoded = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        return decoded
    except jwt.ExpiredSignatureError:
        print("Token expired")
        return None
    except jwt.InvalidTokenError:
        print("Invalid token")
        return None
