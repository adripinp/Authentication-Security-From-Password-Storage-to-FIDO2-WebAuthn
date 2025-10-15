# References:
# - PyOTP docs: https://pyauth.github.io/pyotp/        (TOTP/HOTP usage)        [1]
# - RFC 6238 (TOTP): https://datatracker.ietf.org/doc/html/rfc6238              [2]
# - RFC 4226 (HOTP): https://www.ietf.org/rfc/rfc4226.txt                        [3]
# - Flask Blueprints: https://flask.palletsprojects.com/en/stable/blueprints/    [4]
# - qrcode (Python): https://pypi.org/project/qrcode/                            [5]

from flask import Blueprint, request, jsonify                # Flask imports for routing and JSON responses
import base64, io                                            # For encoding QR image as data URL
import qrcode                                                # QR generator                            [5]
import pyotp                                                 # TOTP/HOTP library (pyotp)               [1]
from . import db                                             # Use your existing DB helpers from Part A

mfa_bp = Blueprint("mfa", __name__, url_prefix="/mfa")       # Define a Blueprint mounted at /mfa       [4]

DEFAULT_TOTP_WINDOW = 1                                      # Allow ±1 timestep (30s) by default      [1][2]
DEFAULT_HOTP_LOOKAHEAD = 3                                   # Check current counter..counter+3        [3]

def _qr_data_url(text: str) -> str:
    img = qrcode.make(text)                                  # Create a QR image for provisioning URI  [5]
    buf = io.BytesIO()                                       # In-memory buffer to avoid writing files
    img.save(buf, format="PNG")                              # Save the PNG image to the buffer
    b64 = base64.b64encode(buf.getvalue()).decode()          # Base64-encode buffer → text
    return f"data:image/png;base64,{b64}"                    # Return as a data URL for <img src=...>

@mfa_bp.post("/totp/enroll")
def totp_enroll():
    data = request.get_json(force=True)                      # Parse JSON body 
    username = data.get("username")                          # Extract username
    user = db.get_user_by_username(username)                 # Load user row 
    if not user:                                             # If user not found
        return jsonify(error="user not found"), 404          
    meta = user.get("mfa_meta", {})                          # Load existing MFA meta dict or {}
    secret = pyotp.random_base32()                           # Generate a new base32 secret             [1]
    meta["totp_secret"] = secret                             # Store secret in mfa_meta
    meta["totp_issuer"] = "AuthDemo"                         # Optional issuer label for QR
    db.update_mfa_meta(user["id"], meta)                     # Persist mfa_meta JSON back to DB
    uri = pyotp.TOTP(secret).provisioning_uri(               # Build otpauth:// URI for authenticator  [1]
        name=username, issuer_name=meta["totp_issuer"]
    )
    return jsonify(secret=secret, uri=uri, qr=_qr_data_url(uri))  # Return secret + URI + QR data URL

@mfa_bp.post("/totp/verify")
def totp_verify():
    data = request.get_json(force=True)                      # Parse JSON body
    username = data.get("username")                          # Extract username
    token = data.get("token")                                # The 6-digit TOTP
    window = int(data.get("window", DEFAULT_TOTP_WINDOW))    # ±window steps (0 or 1)                   [1]
    user = db.get_user_by_username(username)                 # Lookup user
    if not user:                                             # No user -> error
        return jsonify(ok=False, reason="user-not-found"), 404
    secret = user.get("mfa_meta", {}).get("totp_secret")     # Pull TOTP secret from mfa_meta
    if not secret:                                           # Not enrolled yet
        db.mfa_log(user["id"], "totp", False, "not-enrolled")# Log failure in mfa_logs
        return jsonify(ok=False, reason="not-enrolled"), 400
    totp = pyotp.TOTP(secret)                                # Build TOTP object                        [1][2]
    ok = totp.verify(token, valid_window=window)             # Verify, allowing ±window time steps      [1]
    db.mfa_log(user["id"], "totp", bool(ok), f"window={window}")  # Log success/failure
    return jsonify(ok=bool(ok))                              # Return simple OK flag

@mfa_bp.post("/hotp/enroll")
def hotp_enroll():
    data = request.get_json(force=True)                      # Parse JSON
    username = data.get("username")                          # Username
    user = db.get_user_by_username(username)                 # Lookup user
    if not user:                                             # If no user
        return jsonify(error="user not found"), 404
    meta = user.get("mfa_meta", {})                          # Load meta dict
    secret = meta.get("hotp_secret") or pyotp.random_base32()# Reuse or make a new secret               [1]
    meta["hotp_secret"] = secret                             # Save secret
    meta["hotp_counter"] = 0                                 # Start counter at 0                       [3]
    db.update_mfa_meta(user["id"], meta)                     # Persist meta
    db.mfa_log(user["id"], "hotp", True, "enrolled")         # Log enrollment
    return jsonify(ok=True, counter=0)                       # Return initial counter info

@mfa_bp.post("/hotp/verify")
def hotp_verify():
    data = request.get_json(force=True)                      # Parse JSON
    username = data.get("username")                          # Username
    token = data.get("token")                                # HOTP code from user/app
    lookahead = int(data.get("lookahead", DEFAULT_HOTP_LOOKAHEAD))  # How far ahead we accept            [3]
    user = db.get_user_by_username(username)                 # Lookup user
    if not user:                                             # If no user row
        return jsonify(ok=False, reason="user-not-found"), 404
    meta = user.get("mfa_meta", {})                          # Load meta dict
    secret = meta.get("hotp_secret")                         # Require HOTP secret
    if not secret:                                           # If not enrolled
        db.mfa_log(user["id"], "hotp", False, "not-enrolled")# Log failure
        return jsonify(ok=False, reason="not-enrolled"), 400
    ctr = int(meta.get("hotp_counter", 0))                   # Current server counter                    [3]
    hotp = pyotp.HOTP(secret)                                # Build HOTP object                         [1][3]
    matched = None                                           # Track which counter matched (if any)
    for i in range(lookahead + 1):                           # Try ctr, ctr+1, ..., ctr+lookahead        [3]
        if hotp.verify(token, ctr + i):                      # Verify at this counter
            matched = ctr + i                                # Record matched counter
            break                                            # Stop at first match
    if matched is not None:                                  # If success
        meta["hotp_counter"] = matched + 1                   # Advance counter to prevent replay         [3]
        db.update_mfa_meta(user["id"], meta)                 # Save new counter
        db.mfa_log(user["id"], "hotp", True, f"matched={matched}") # Log success
        return jsonify(ok=True, matched_counter=matched, new_counter=matched + 1)
    else:                                                    # If nothing matched
        db.mfa_log(user["id"], "hotp", False, f"ctr={ctr},lookahead={lookahead}") # Log failure
        return jsonify(ok=False, reason="no-match", counter=ctr), 401
