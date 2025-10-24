import os, gzip, shutil, datetime
src = "/app/dbdata/db.sqlite3"
dst = f"/app/backups/sqlite-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.db.gz"
os.makedirs("/app/backups", exist_ok=True)
with open(src, "rb") as f_in, gzip.open(dst, "wb") as f_out:
    shutil.copyfileobj(f_in, f_out)
print(f"[backup] saved {dst}")
