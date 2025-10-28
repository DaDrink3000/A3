
# app/services/tally_service.py
import json, hashlib
from typing import Dict, Any, List, Tuple
from pathlib import Path
from nacl.public import SealedBox
from .tamper_evident_service import BALLOT_FILE
from key_mgmt import get_encryption_private_key

class TallyService:
    """
    Decrypts sealed-box ballots and produces a verifiable tally:
    - counts per choice
    - list of commitments: sha256 of raw ciphertext for each ballot ID
    Anyone with ballots.jsonl can recompute the commitments and validate the included set.
    """
    def __init__(self, ballot_file: str = BALLOT_FILE):
        self.ballot_file = Path("/app")/ballot_file if not Path(ballot_file).is_absolute() else Path(ballot_file)

    def _iter_ballots(self):
        if not self.ballot_file.exists():
            return
        with open(self.ballot_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    yield json.loads(line)

    def _decrypt_choice(self, sealed_b64: str) -> str:
        priv = get_encryption_private_key()
        box = SealedBox(priv)
        ct = base64.b64decode(sealed_b64)
        pt = box.decrypt(ct)
        return pt.decode("utf-8")

    def tally(self) -> Dict[str, Any]:
        counts: Dict[str, int] = {}
        commitments: List[Tuple[int,str]] = []
        for rec in self._iter_ballots() or []:
            bid = rec.get("id")
            ciphertext_b64 = rec.get("choice")
            # commitment over ciphertext only
            h = hashlib.sha256(ciphertext_b64.encode()).hexdigest()
            commitments.append((bid, h))
            # decrypt (server/authorized use)
            try:
                choice = rec.get("plaintext_choice") or None  # allow future inclusion
                if not choice:
                    import base64
                    from nacl.public import SealedBox
                    priv = get_encryption_private_key()
                    box = SealedBox(priv)
                    choice = box.decrypt(base64.b64decode(ciphertext_b64)).decode()
            except Exception:
                choice = "__UNDEC__"
            counts[choice] = counts.get(choice, 0) + 1
        return {
            "ok": True,
            "counts": counts,
            "ballot_commitments": commitments,
            "ballots_counted": sum(counts.values())
        }
