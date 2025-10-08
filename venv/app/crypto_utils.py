import hashlib, os, base64, bcrypt
from argon2 import PasswordHasher
import sha3
from hmac import compare_digest
import json
import os

PEPPER = os.getenv("PEPPER", "")

def generate_salt(length=16):
    return base64.b64encode(os.urandom(length)).decode('utf-8')

def hash_password(algorithm, password, salt=None, pepper=None, cost_params=None):
    salt = salt or generate_salt()
    pepper = pepper or PEPPER
    password_bytes = (password + (pepper or "")).encode('utf-8')

    if algorithm.lower() == "sha256":
        h = hashlib.sha256(salt.encode() + password_bytes).hexdigest()
    elif algorithm.lower() == "sha3":
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

def verify_password(stored_json, password, pepper=None):
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
