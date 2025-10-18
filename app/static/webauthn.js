// Minimal helpers for WebAuthn demo flows.
function toUint8(v) {
  // Convert ArrayBuffer or TypedArray to Uint8Array; pass through other types.
  if (v == null) return v;
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
  return v;
}

async function cborPost(url, obj) {
  // Send a CBOR-encoded request body and decode CBOR response.
  const body = window.CBOR.encode(obj);
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/cbor", "Accept": "application/cbor" },
    body,
    credentials: "same-origin",             // include session
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`HTTP ${res.status} ${res.statusText}: ${text}`);
  }
  const buf = await res.arrayBuffer();
  return window.CBOR.decode(buf);
}

async function jsonPost(url, obj) {
  // Send a JSON request body and decode a CBOR response (server returns CBOR).
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Accept": "application/cbor" },
    body: JSON.stringify(obj),
    credentials: "same-origin",
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`HTTP ${res.status} ${res.statusText}: ${text}`);
  }
  const buf = await res.arrayBuffer();
  return window.CBOR.decode(buf);
}

/* Registration */
export async function handleRegisterClick({username}) {
  // asks server for PublicKeyCredentialCreationOptions (CBOR -> object)
  const options = await jsonPost("/webauthn/api/register", { username });
  const pk = options.publicKey || options;

  // Convert binary-like fields into Uint8Arrays as required by WebAuthn.
  const publicKey = {
    ...pk,
    challenge: toUint8(pk.challenge),
    user: {
      ...pk.user,
      id: toUint8(pk.user.id),
    },
    excludeCredentials: (pk.excludeCredentials || []).map(c => ({
      ...c,
      id: toUint8(c.id),
    })),
  };

  // Trigger platform authenticator/roaming authenticator UI.
  const cred = await navigator.credentials.create({ publicKey });
  if (!cred) throw new Error("navigator.credentials.create() returned null");

  // Package authenticator response back to server (CBOR payload expected).
  const payload = {
    clientDataJSON: toUint8(cred.response.clientDataJSON),
    attestationObject: toUint8(cred.response.attestationObject),
  };
  return await cborPost("/webauthn/api/register/complete", payload);
}

/* Authentication */
export async function handleLoginClick({ username }) {
  // Ask server for PublicKeyCredentialRequestOptions (assertion request)
  const options = await jsonPost("/webauthn/api/authenticate", { username });
  const pk = options.publicKey || options;
  const publicKey = {
    ...pk,
    challenge: toUint8(pk.challenge),
    allowCredentials: (pk.allowCredentials || []).map(c => ({
      ...c,
      id: toUint8(c.id),
    })),
  };

  console.log("about to call navigator.credentials.get", publicKey);
  try {
    const assertion = await navigator.credentials.get({ publicKey });
    console.log("got assertion", assertion); 
  } catch (e) {
    console.error("navigator.credentials.get failed:", e);
    throw e;
  }

  const payload = {
    credentialId: toUint8(assertion.rawId),
    clientDataJSON: toUint8(assertion.response.clientDataJSON),
    authenticatorData: toUint8(assertion.response.authenticatorData),
    signature: toUint8(assertion.response.signature),
  };
  return await cborPost("/webauthn/api/authenticate/complete", payload);
}
