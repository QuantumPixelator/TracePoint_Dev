import hmac
import hashlib

SECRET_KEY = b'supersecretkey'  # Use a secure key in production

def generate_token(email):
    return hmac.new(SECRET_KEY, email.encode(), hashlib.sha256).hexdigest()

def check_token(token, email):
    expected_token = generate_token(email)
    return hmac.compare_digest(expected_token, token)
