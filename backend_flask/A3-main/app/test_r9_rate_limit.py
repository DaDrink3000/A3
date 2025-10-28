import requests
import time

BASE_URL = "http://127.0.0.1:8001/healthz"
TOTAL_REQUESTS = 65   # Send 65 requests to exceed 60/min limit

print(f"[R09 Test] Sending {TOTAL_REQUESTS} requests to {BASE_URL} ...")

retry_after = None

for i in range(1, TOTAL_REQUESTS + 1):
    resp = requests.get(BASE_URL)
    status = resp.status_code
    retry_after = resp.headers.get("Retry-After")

    if status == 200:
        print(f"[{i:02}] OK (200)")
    elif status == 429:
        print(f"[{i:02}] Rate limit hit! (429 Too Many Requests)")
        print("     Retry-After:", retry_after)
        print("     Response JSON:", resp.json())
        break
    else:
        print(f"[{i:02}] Unexpected status:", status, resp.text)

# Optional: Try again after waiting for Retry-After period
if retry_after:
    wait_time = int(retry_after)
    print(f"\nWaiting {wait_time} seconds before retrying...")
    time.sleep(wait_time + 1)

    print("[Retry Test] Sending one more request after cooldown...")
    resp = requests.get(BASE_URL)
    print("   Status:", resp.status_code)
    print("   Response:", resp.text)
