import base64
import requests
import nacl.public
import nacl.utils

# --- Configuration ---
BASE_URL = "http://127.0.0.1:8001"
VOTER_ID = "voter123"
CHOICE = "Candidate_A"  

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

# --- Step 3: Submit encrypted ballot ---
print("[3] Submitting encrypted ballot to /ballot ...")
payload = {
    "voter_id": VOTER_ID,
    "ciphertext": ciphertext_b64
}

resp = requests.post(f"{BASE_URL}/ballot", json=payload)
print("   → Status code:", resp.status_code)
print("   → Response:", resp.json())

