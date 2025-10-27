import os, json, time, argparse, sys, base64, tarfile, io
from pathlib import Path
from typing import Dict, Any
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature
from nacl.public import PrivateKey as CurvePrivateKey

from pathlib import Path

KEYDIR = Path("/app/keys")          
META   = KEYDIR / "inventory.json"   
ENC_KEYDIR = KEYDIR / "encryption"   

# ---------- meta ----------
def load_meta() -> Dict[str, Any]:
    if META.exists():
        return json.loads(META.read_text())
    return {"keys": []}  # [{kid, status: active|retiring|retired, created: epoch}]

def save_meta(meta: Dict[str, Any]):
    KEYDIR.mkdir(parents=True, exist_ok=True)
    META.write_text(json.dumps(meta, indent=2))

from typing import Optional
def active_kid(meta) -> Optional[str]:
    for k in meta["keys"]:
        if k["status"] == "active":
            return k["kid"]
    return None

def pem_paths(kid: str):
    return (KEYDIR / f"{kid}.priv.pem", KEYDIR / f"{kid}.pub.pem")

# ---------- crypto ----------
def gen_pair(kid: str):
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key()
    priv = sk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub = pk.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_path, pub_path = pem_paths(kid)
    priv_path.write_bytes(priv); os.chmod(priv_path, 0o600)
    pub_path.write_bytes(pub)

def load_private(kid: str):
    priv_path, _ = pem_paths(kid)
    return serialization.load_pem_private_key(priv_path.read_bytes(), password=None)

def load_public(kid: str):
    _, pub_path = pem_paths(kid)
    return serialization.load_pem_public_key(pub_path.read_bytes())

# ---------- backup helpers (AES-GCM with scrypt KDF) ----------
def kdf_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)
    return kdf.derive(passphrase.encode("utf-8"))

def aesgcm_encrypt(passphrase: str, plaintext: bytes) -> bytes:
    salt = os.urandom(16)
    key  = kdf_from_passphrase(passphrase, salt)
    aes  = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, None)
    return b"BK1" + salt + nonce + ct  # simple header

def aesgcm_decrypt(passphrase: str, blob: bytes) -> bytes:
    if not blob.startswith(b"BK1"):
        raise ValueError("bad backup format")
    salt, nonce, ct = blob[3:19], blob[19:31], blob[31:]
    key = kdf_from_passphrase(passphrase, salt)
    aes = AESGCM(key)
    return aes.decrypt(nonce, ct, None)

def tar_keys() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        # include inventory.json and all *.pem
        for p in [META] + list(KEYDIR.glob("*.pem")):
            if p.exists():
                tar.add(p, arcname=p.name)
    return buf.getvalue()

def untar_to_keys(blob: bytes):
    KEYDIR.mkdir(parents=True, exist_ok=True)
    buf = io.BytesIO(blob)
    with tarfile.open(fileobj=buf, mode="r") as tar:
        tar.extractall(KEYDIR)

# ---------- CLI commands ----------
def cmd_generate(args):
    meta = load_meta()
    for k in meta["keys"]:
        if k["status"] == "active":
            k["status"] = "retiring"
    kid = f"K{int(time.time())}"
    gen_pair(kid)
    meta["keys"].append({"kid": kid, "status": "active", "created": int(time.time())})
    save_meta(meta)
    print(f"Generated {kid} (active).")

def cmd_list(args):
    print(json.dumps(load_meta(), indent=2))

def cmd_sign(args):
    meta = load_meta()
    kid = args.kid or active_kid(meta)
    if not kid:
        print("No active key. Run generate first.", file=sys.stderr); sys.exit(1)
    sk = load_private(kid)
    data = Path(args.file).read_bytes()
    sig = sk.sign(data)
    print(json.dumps({"kid": kid, "alg": "Ed25519", "sig": base64.b64encode(sig).decode()}, indent=2))

def cmd_verify(args):
    payload = json.loads(Path(args.signature_json).read_text()) if args.signature_json.endswith(".json") \
              else json.loads(args.signature_json)
    kid = payload["kid"]
    sig = base64.b64decode(payload["sig"])
    pk = load_public(kid)
    data = Path(args.file).read_bytes()
    try:
        pk.verify(sig, data)
        print("OK: signature valid")
    except InvalidSignature:
        print("FAIL: invalid signature", file=sys.stderr); sys.exit(2)

def cmd_retire(args):
    meta = load_meta()
    for k in meta["keys"]:
        if k["kid"] == args.kid:
            k["status"] = "retired"; save_meta(meta); print(f"Retired {args.kid}"); return
    print("KID not found", file=sys.stderr); sys.exit(1)

def cmd_backup(args):
    if not args.passphrase:
        print("Provide --passphrase", file=sys.stderr); sys.exit(1)
    blob = tar_keys()
    enc  = aesgcm_encrypt(args.passphrase, blob)
    Path(args.out).write_bytes(enc)
    print(f"Encrypted backup written to {args.out}")

def cmd_restore(args):
    if not args.passphrase:
        print("Provide --passphrase", file=sys.stderr); sys.exit(1)
    enc = Path(args.backup_file).read_bytes()
    blob = aesgcm_decrypt(args.passphrase, enc)
    untar_to_keys(blob)
    print("Keys restored from backup.")


# ---------- sealed-box encryption keys ----------

def ensure_encryption_keys():
    """Ensure an X25519 keypair exists for ballot encryption."""
    ENC_KEYDIR.mkdir(parents=True, exist_ok=True)
    priv_file = ENC_KEYDIR / "enc_priv.key"
    pub_file = ENC_KEYDIR / "enc_pub.key"

    if not (priv_file.exists() and pub_file.exists()):
        priv = CurvePrivateKey.generate()
        pub = priv.public_key
        priv_file.write_bytes(priv.encode())
        pub_file.write_bytes(pub.encode())
        os.chmod(priv_file, 0o600)

    priv = CurvePrivateKey(priv_file.read_bytes())
    pub = priv.public_key
    return priv, pub


def get_encryption_public_key_b64() -> str:
    """Return the base64-encoded public key for sealed-box encryption."""
    _, pub = ensure_encryption_keys()
    return base64.b64encode(pub.encode()).decode("utf-8")


def get_encryption_private_key():
    """Return the X25519 private key (for server-side decryption/testing only)."""
    priv, _ = ensure_encryption_keys()
    return priv

def main():
    KEYDIR.mkdir(parents=True, exist_ok=True)
    p = argparse.ArgumentParser(prog="keytool", description="Ed25519 key mgmt + backup")
    sub = p.add_subparsers(required=True)

    sub.add_parser("generate").set_defaults(func=cmd_generate)
    sub.add_parser("list").set_defaults(func=cmd_list)

    s = sub.add_parser("sign");   s.add_argument("file"); s.add_argument("--kid"); s.set_defaults(func=cmd_sign)
    v = sub.add_parser("verify"); v.add_argument("file"); v.add_argument("signature_json"); v.set_defaults(func=cmd_verify)

    r = sub.add_parser("retire"); r.add_argument("kid"); r.set_defaults(func=cmd_retire)

    b = sub.add_parser("backup"); b.add_argument("--passphrase", required=True); b.add_argument("--out", default="/app/keys/backup.enc"); b.set_defaults(func=cmd_backup)
    x = sub.add_parser("restore"); x.add_argument("backup_file"); x.add_argument("--passphrase", required=True); x.set_defaults(func=cmd_restore)

    args = p.parse_args(); args.func(args)




if __name__ == "__main__":
    main()
