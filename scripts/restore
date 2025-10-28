import os, gzip, shutil, sys
if len(sys.argv) < 2:
    print("Usage: restore.py <file>")
    sys.exit(1)
src = f"/app/backups/{sys.argv[1]}"
dst = "/app/dbdata/db.sqlite3"
with gzip.open(src, "rb") as f_in, open(dst, "wb") as f_out:
    shutil.copyfileobj(f_in, f_out)
print(f"[restore] restored {src} -> {dst}")
