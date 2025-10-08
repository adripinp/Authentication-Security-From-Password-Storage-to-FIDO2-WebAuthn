import hashlib
import os
import base64
import bcrypt
from argon2 import PasswordHasher
from hmac import compare_digest
import json

# Load PEPPER from environment (defined in .env or system)
PEPPER = os.getenv("PEPPER", "")

# ---------------------------
# Generate a random salt
# ---------------------------
def generate_salt(length=16):
    """Generate a random base64-encoded salt."""
    return base64.b64encode(os.urandom(length)).decode('utf-8')


# ---------------------------
# Hash a password
# ---------------------------
def hash_password(algorithm, password, salt=None, pepper=None, cost_params=None):
    """Hash password using selected algorithm and optional salt/pepper."""
    salt = salt or generate_salt()
    pepper = pepper or PEPPER
    password_bytes = (password + (pepper or "")).encode('utf-8')

    # Choose algorithm
    if algorithm.lower() == "sha256":
        h = hashlib.sha256(salt.encode() + password_bytes).hexdigest()
    elif algorithm.lower() == "sha3":
        # Uses hashlib’s built-in SHA3 implementation
        h = hashlib.sha3_256(salt.encode() + password_bytes).hexdigest()
    elif algorithm.lower() == "bcrypt":
        h = bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode()
    elif algorithm.lower() == "argon2":
        ph = PasswordHasher()
        h = ph.hash(password_bytes.decode())
    else:
        raise ValueError("Unsupported algorithm")

    return json.dumps({
        "algo": algorithm,
        "salt": salt,
        "hash": h,
        "cost_params": cost_params
    })


# ---------------------------
# Verify password
# ---------------------------
def verify_password(stored_json, password, pepper=None):
    """Verify password against stored hash."""
    data = json.loads(stored_json)
    algo = data["algo"]
    salt = data.get("salt")
    stored_hash = data["hash"]
    pepper = pepper or PEPPER

    password_bytes = (password + (pepper or "")).encode('utf-8')

    if algo.lower() == "sha256":
        return compare_digest(stored_hash, hashlib.sha256(salt.encode() + password_bytes).hexdigest())
    elif algo.lower() == "sha3":
        return compare_digest(stored_hash, hashlib.sha3_256(salt.encode() + password_bytes).hexdigest())
    elif algo.lower() == "bcrypt":
        return bcrypt.checkpw(password_bytes, stored_hash.encode())
    elif algo.lower() == "argon2":
        ph = PasswordHasher()
        try:
            ph.verify(stored_hash, password_bytes.decode())
            return True
        except:
            return False
    else:
        return False
