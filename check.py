import hashlib
secret_mod = 18446744073709551615

# Doesn't actually add any cryptographic complexity

def generate_token(Email):
    hashed_role = int(hashlib.sha256(Email.encode()).hexdigest(), 16) % secret_mod
    return str(hashed_role)

def check_token(token, Email):
    hashed_role = int(hashlib.sha256(Email.encode()).hexdigest(), 16) % secret_mod
    token = int(token)
    return hashed_role == token
