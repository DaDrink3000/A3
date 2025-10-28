
# app/middleware.py
import ipaddress, os
from flask import request, jsonify

ALLOWED_CIDRS = os.getenv("ALLOWED_CIDRS", "").split(",") if os.getenv("ALLOWED_CIDRS") else []
ALLOWED_COUNTRY = os.getenv("ALLOWED_COUNTRY", "AU")

def client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"

def ip_in_allowed_ranges() -> bool:
    if not ALLOWED_CIDRS:
        return True  # no restriction configured
    try:
        ip = ipaddress.ip_address(client_ip())
        for cidr in ALLOWED_CIDRS:
            if ip in ipaddress.ip_network(cidr.strip()):
                return True
        return False
    except Exception:
        return False

def country_allowed() -> bool:
    # In production, resolve via GeoIP; for prototype accept dev header
    ctry = request.headers.get("X-Test-Country", "UNKNOWN").upper()
    return (ALLOWED_COUNTRY is None) or (ctry == ALLOWED_COUNTRY)

def enforce_geo():
    if not ip_in_allowed_ranges() or not country_allowed():
        return jsonify(error="geofenced: access not allowed from your region/network"), 451
    return None
