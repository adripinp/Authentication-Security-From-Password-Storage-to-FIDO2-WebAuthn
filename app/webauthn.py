# Insperation from https://github.com/kevbradwick/python-fido2-webauthn-demo
"""
Blueprint implementing WebAuthn registration and authentication flows
using python-fido2. This module exposes four routes:

POST /api/register -> begin registration (returns creation options)
POST /api/register/complete -> finish registration (persists credential)
POST /api/authenticate -> begin authentication (returns request options)
POST /api/authenticate/complete -> finish authentication (verifies assertion)

Notes
-----
* This demo stores an in-memory cache of credentials per user (_user_creds).
The database remains the source of truth; the cache avoids decoding on every
request. For a real app, they should be reconstructed from DB at startup or on
demand.
* All CBOR payloads are encoded/decoded using fido2.cbor helpers.
* The servers origin check is intentionally strict (localhost only by default).
"""
from __future__ import annotations
from collections import defaultdict
import os
from typing import List
from fido2.cbor import decode as cbor_decode
from flask import Blueprint, request, abort, session
from fido2 import cbor
from fido2.server import Fido2Server
from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    UserVerificationRequirement,
    AttestationObject,
    CollectedClientData,
    AuthenticatorData,
    AttestedCredentialData,
    PublicKeyCredentialDescriptor,
    AttestedCredentialData, 
    Aaguid
)

from . import db as DB

# Relying Party (RP) config
# RP ID must match the effective domain used in the browser.
RP_ID = os.environ.get("RP_ID", "localhost")
RP_NAME = os.environ.get("RP_NAME", "Auth Security Lab")

# Allowed web origins for requests hitting this server (scheme + host + port).
# These are validated via Fido2Server.verify_origin callback.
ALLOWED_ORIGINS = {"http://localhost:5000"}  

# In-memory cache mapping user_id -> list[AttestedCredentialData]
# Used by the demo to avoid hitting the DB on every auth request.
_user_creds = defaultdict(list)                                  


def _verify_origin(origin: str) -> bool:
    """Return True iff the browser-provided origin is explicitly allowed."""
    return origin in ALLOWED_ORIGINS

# Initialize the FIDO2 server with RP metadata and custom origin verifier.
_server = Fido2Server(PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME), verify_origin=_verify_origin)

# Register blueprint
webauthn_bp = Blueprint("webauthn", __name__)



def _exclude_list_for_user(user_id: int) -> List[PublicKeyCredentialDescriptor]:
    """Return a list of credential descriptors to exclude during registration.

    Browsers will skip authenticators that already contain any of these IDs,
    preventing duplicate registrations for the same authenticator.
    """
    ids = DB.webauthn_list_credentials(user_id)
    return [PublicKeyCredentialDescriptor(type="public-key", id=cid) for cid in ids]

# Registration
@webauthn_bp.post("/webauthn/api/register")
def register_begin():
    """
    Begin the registration ceremony.

    Request JSON: { "userId": <int>, "userName": <str>, "displayName": <str> }
    Response CBOR: PublicKeyCredentialCreationOptions (dict with bytes)
    """
    data = request.get_json(force=True, silent=True) or {}
    try:
        username = data["username"].strip()
    except Exception:
        return abort(400)

    user_row = DB.get_user_by_username(username)
    if not user_row:
        print('ERR: unknown user')
        return abort(404)
    user_id = user_row["id"]


    # PublicKeyCredentialUserEntity requires the ID as bytes.
    pk_user = PublicKeyCredentialUserEntity(
        name=username,
        id=str(user_id).encode("utf-8"),
        display_name=username,
    )

    exclude = _exclude_list_for_user(user_id)

    # Build options
    options, state = _server.register_begin(
        user=pk_user,
        credentials=exclude,
        user_verification=UserVerificationRequirement.DISCOURAGED,
        authenticator_attachment=None,          # Allow both cross-platform & platform
    )

    # Store both state and user_id in session
    session["reg"] = {"state": state, "user_id": user_id}
    return cbor.encode(options)

@webauthn_bp.post("/webauthn/api/register/complete")
def register_complete():
    """
    Finish the registration ceremony.

    Request CBOR: { userId, clientDataJSON, attestationObject }
    Response CBOR: { status: "ok" }
    """
    data = cbor.decode(request.get_data() or b"")
    try:    
        client_data = CollectedClientData(data["clientDataJSON"])           # bytes -> obj
        att_obj = AttestationObject(data["attestationObject"])              # bytes -> obj
    except Exception:
        return abort(400)

    reg_session = session.get("reg")
    if not reg_session:
        return abort(400)
    
    state = reg_session["state"]
    user_id = reg_session["user_id"]

    # Validate attestation, extract attested credential data & public key.
    reg = _server.register_complete(state, client_data, att_obj)
    cred = reg.credential_data
    if not cred:
        return abort(400)

    credential_id = cred.credential_id                  # bytes
    public_key_cose = cbor.encode(cred.public_key)      # bytes (COSE)
    sign_count = getattr(reg, "sign_count", getattr(reg, "counter", 0)) or 0
    
    # Store credential; UNIQUE(user_id, credential_id) prevents dupes.
    DB.webauthn_save_credential(user_id, RP_ID, credential_id, public_key_cose, sign_count)

    # Cache it in memory for this process lifetime (demo convenience).
    _user_creds[user_id].append(cred)

    # clear state
    session.pop("reg", None)
    return cbor.encode({"status": "ok"})

# Authentication 
@webauthn_bp.post("/webauthn/api/authenticate")
def authenticate_begin():
    """Begin the authentication ceremony; returns assertion request options."""
    data = request.get_json(force=True, silent=True) or {}
    try:
        username = data["username"].strip()            # Which user account to authenticate
    except Exception:
        return abort(400)
    
    user_row = DB.get_user_by_username(username)
    if not user_row:
        return abort(404)
    user_id = user_row["id"]

    # check if in-memory
    user_creds = _user_creds.get(user_id, [])
    if not user_creds:
        # should try to load from DB; not implemented
        return cbor.encode({"error": "no credentials registered for user"}), 400

    options, state = _server.authenticate_begin(user_creds)

    # store state + user_id for completion
    session["auth"] = {"state": state, "user_id": user_id}
    return cbor.encode(options)


@webauthn_bp.post("/webauthn/api/authenticate/complete")
def authenticate_complete():
    """Finish authentication by verifying the authenticator's assertion."""
    data = cbor.decode(request.get_data() or b"")
    try:
        credential_id = data["credentialId"]                                # bytes
        client_data = CollectedClientData(data["clientDataJSON"])           # bytes -> obj
        auth_data = AuthenticatorData(data["authenticatorData"])            # bytes -> obj
        signature = data["signature"]                                       # bytes
    except Exception:
        return abort(400)
    
    auth_session = session.get("auth")
    if not auth_session:
        return abort(400)

    state = auth_session["state"]
    user_id = auth_session["user_id"]

    user_creds = _user_creds.get(user_id, [])
    if not user_creds:
        # should try to load from DB
        return abort(400)

    # python-fido2 will identify the matching stored credential by ID and
    # verify the signature over clientDataHash + authenticatorData.
    _server.authenticate_complete(
        state,
        user_creds,          
        credential_id,
        client_data,
        auth_data,
        signature,
    )
    # Read previous count from DB (if any)
    row = DB.webauthn_get_credential(user_id, credential_id)  # -> (public_key_bytes, prev_count) or None
    prev_count = row[1] if row else 0
    
    # Get new count from authenticatorData
    new_count = getattr(auth_data, "sign_count", getattr(auth_data, "counter", 0)) or 0

    if new_count == 0:
        # Authenticator doesn't support counters; nothing to update.
        pass
    elif prev_count > 0 and new_count <= prev_count:
        # Potentially cloned authenticator; choose policy. For dev, just log.
        DB.mfa_log(user_id, "webauthn", False, f"Non-incrementing counter: prev={prev_count}, new={new_count}")
    else:
        # Monotonic increase → persist
        DB.webauthn_update_sign_count(user_id, credential_id, new_count)

    # Clear state
    session.pop("auth", None)
    return cbor.encode({"status": "OK"})
