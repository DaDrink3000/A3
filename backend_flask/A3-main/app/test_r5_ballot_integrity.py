import base64
import json
import os
import time
import hmac
import hashlib
import requests
import nacl.public
import nacl.utils

# --- Configuration ---
BASE_URL = "http://127.0.0.1:8001"
VOTER_ID = "voterR5"
CHOICE = "Candidate_X"

# --- Shared secret for HMAC (for testing only!) ---
# In production, client and server would share this securely.
HMAC_KEY = b"TEST_SHARED_SECRET_KEY_FOR_R5"

# --- Helper: compute HMAC same as server ---
def compute_hmac(data: bytes) -> str:
    tag = hmac.new(HMAC_KEY, data, hashlib.sha256).digest()
    return base64.b64encode(tag).decode()

# --- Step 1: Get the public key from the server ---
print("[1] Fetching /public-key ...")
resp = requests.get(f"{BASE_URL}/public-key")
resp.raise_for_status()
public_key_b64 = resp.json()["public_key"]
print("   → Public key (base64):", public_key_b64)

# --- Step 2: Encrypt the ballot using sealed box ---
print("[2] Encrypting ballot client-side ...")
public_key_bytes = base64.b64decode(public_key_b64)
public_key = nacl.public.PublicKey(public_key_bytes)
sealed_box = nacl.public.SealedBox(public_key)

ciphertext = sealed_box.encrypt(CHOICE.encode("utf-8"))
ciphertext_b64 = base64.b64encode(ciphertext).decode("utf-8")
print("   → Ciphertext (base64):", ciphertext_b64[:60] + "...")

# --- Step 3: Build the ballot envelope with integrity metadata ---
nonce = base64.b64encode(os.urandom(8)).decode()
timestamp = time.time()

envelope_data = f"{VOTER_ID}:{ciphertext_b64}:{nonce}:{timestamp}".encode()
tag_b64 = compute_hmac(envelope_data)

payload = {
    "voter_id": VOTER_ID,
    "ciphertext": ciphertext_b64,
    "nonce": nonce,
    "timestamp": timestamp,
    "hmac": tag_b64
}

print("[3] Submitting encrypted ballot (valid case) ...")
resp = requests.post(f"{BASE_URL}/ballot", json=payload)
print("   → Status code:", resp.status_code)
print("   → Response:", resp.json())

# --- Step 4: Replay the same nonce to test replay rejection ---
print("\n[4] Replaying the same ballot to test replay detection ...")
resp = requests.post(f"{BASE_URL}/ballot", json=payload)
print("   → Status code:", resp.status_code)
print("   → Response:", resp.json())

# --- Step 5: Test invalid HMAC ---
print("\n[5] Submitting ballot with invalid HMAC ...")
bad_payload = payload.copy()
bad_payload["nonce"] = base64.b64encode(os.urandom(8)).decode()
bad_payload["hmac"] = "AAAA_INVALID_TAG"
resp = requests.post(f"{BASE_URL}/ballot", json=bad_payload)
print("   → Status code:", resp.status_code)
print("   → Response:", resp.json())

# --- Step 6: Test stale timestamp ---
print("\n[6] Submitting stale ballot (timestamp too old) ...")
old_payload = payload.copy()
old_payload["nonce"] = base64.b64encode(os.urandom(8)).decode()
old_payload["timestamp"] = time.time() - 9999  # older than 5 min
old_envelope = f"{old_payload['voter_id']}:{old_payload['ciphertext']}:{old_payload['nonce']}:{old_payload['timestamp']}".encode()
old_payload["hmac"] = compute_hmac(old_envelope)
resp = requests.post(f"{BASE_URL}/ballot", json=old_payload)
print("   → Status code:", resp.status_code)
print("   → Response:", resp.json())
