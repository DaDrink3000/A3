# app/routes/tally_routes.py
from flask import Blueprint, jsonify
from security.rbac import require_roles
from services.tally_service import TallyService

bp = Blueprint("tally", __name__)

@bp.get("/tally")
@require_roles("auditor", "admin")
def get_tally():
    svc = TallyService()
    res = svc.tally()
    return jsonify(res)
