from flask import Blueprint, request, jsonify, g
from .constants import * # Assuming constants.py is in the same package
from .utils import (
    get_client_ip,
    get_user_id
)
from services import IntegrityException # Assuming services is importable
from key_mgmt import get_encryption_public_key_b64,verify_hmac
import base64, json, time
recent_nonces = set()
MAX_NONCE_AGE = 60 * 5  

# Initialize Blueprint
voting_bp = Blueprint('voting', __name__)

from services import (
    BallotEvidentService,
    BlockchainVerificationService,
    EligibilityService,
    AuditLoggingService
)

def get_ballot_service():
    return BallotEvidentService()

def get_verification_service():
    return BlockchainVerificationService()

def get_eligibility_service():
    return EligibilityService()

def get_audit_service():
    return AuditLoggingService(log_dir="audit_logs", rotation_when="midnight", backup_count=365)



# General endpoint

@voting_bp.route('/')
def index():
    # Root endpoint
    return {
        'message': 'Voting System API',
        'services': {
            'users': '/register (POST), /users (GET), /user/<id> (GET), /user/email/<email> (GET)',
            'ballots': '/ballot (POST), /ballots (GET)',
            'verification': '/verify (GET), /hashes (GET), /blockchain-stats (GET)',
            'eligibility': '/voter/<id> (GET), /voter?id=<id> (GET), /voter-stats (GET)',
            'audit': '/audit-stats (GET), /verify-audit-log (GET)'
        }
    }

@voting_bp.route('/health')
def health():
    # Health check - not audited
    return {'status': STATUS_HEALTHY}

#===================== Updated and added code  for R4 ==========================
@voting_bp.route("/public-key", methods=["GET"])
def get_public_key():
    """
    Expose the public key for client-side sealed-box encryption.
    Clients use this to encrypt their ballots before submission.
    """
    return jsonify({
        "public_key": get_encryption_public_key_b64()
    }), 200


# Modified ballot endpoint for R5 Requirement
@voting_bp.route('/ballot', methods=['POST'])
def cast_ballot():
    """
    Accepts a sealed (encrypted) ballot envelope with HMAC integrity.
    Required fields:
      voter_id, ciphertext, nonce, timestamp, hmac
    """
    data = request.get_json(silent=True) or {}
    required = {"voter_id", "ciphertext", "nonce", "timestamp", "hmac"}
    if not required.issubset(data):
        return jsonify({
            "success": False,
            "error": f"missing fields; required: {sorted(required)}"
        }), 400

    voter_id = data["voter_id"]
    ciphertext_b64 = data["ciphertext"]
    nonce = data["nonce"]
    ts = data["timestamp"]
    tag = data["hmac"]

    # Validate timestamp freshness
    now = time.time()
    try:
        ts = float(ts)
    except ValueError:
        return jsonify({"success": False, "error": "invalid timestamp"}), 400

    if abs(now - ts) > MAX_NONCE_AGE:
        return jsonify({"success": False, "error": "stale ballot timestamp"}), 400

    # Replay protection
    if nonce in recent_nonces:
        return jsonify({"success": False, "error": "replay detected"}), 409
    recent_nonces.add(nonce)

    # Verify HMAC
    envelope_data = f"{voter_id}:{ciphertext_b64}:{nonce}:{ts}".encode()
    if not verify_hmac(envelope_data, tag):
        return jsonify({"success": False, "error": "invalid HMAC"}), 401

    # Optional: validate candidate ID structure in ciphertext (if included)
    # You can later decrypt for audit/verification

    # Proceed to add encrypted ballot
    ballot_service = get_ballot_service()
    try:
        ballot = ballot_service.add_ballot(voter_id, ciphertext_b64)
        total = ballot_service.get_ballot_count()

        return jsonify({
            "success": True,
            "ballot": ballot,
            "total_ballots": total
        }), 200

    except IntegrityException as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 409

# @voting_bp.route('/ballot', methods=['POST'])
# def cast_ballot():
#     """
#     Accepts a sealed (encrypted) ballot from the client.
#     The server never sees the plaintext vote.
#     """
#     data = request.get_json(silent=True) or {}
#     voter_id = data.get('voter_id')
#     ciphertext = data.get('ciphertext')

#     if not voter_id or not ciphertext:
#         return jsonify({
#             'success': False,
#             'error': 'voter_id and ciphertext required'
#         }), 400

#     ballot_service = get_ballot_service()  

#     try:
#         ballot = ballot_service.add_ballot(voter_id, ciphertext)
#         total = ballot_service.get_ballot_count()

#         return jsonify({
#             'success': True,
#             'ballot': ballot,
#             'total_ballots': total
#         }), 200

#     except IntegrityException as e:
#         return jsonify({
#             'success': False,
#             'error': str(e)
#         }), 409




# # Ballot endpoints

# @voting_bp.route('/ballot', methods=['POST'])
# def add_ballot():
#     # Add a new ballot
#     ballot_service = get_ballot_service()
#     data = request.json
#     voter_id = data.get(BALLOT_VOTER_ID)
#     choice = data.get(BALLOT_CHOICE)
    
#     if not voter_id or not choice:
#         return jsonify({RESP_ERROR: 'voter_id and choice required'}), HTTP_BAD_REQUEST
    
#     try:
#         ballot = ballot_service.add_ballot(voter_id, choice)
#         total = ballot_service.get_ballot_count()
        
#         return jsonify({
#             RESP_SUCCESS: True,
#             RESP_BALLOT: ballot,
#             RESP_TOTAL_BALLOTS: total
#         })
#     except IntegrityException as e:
#         return jsonify({
#             RESP_SUCCESS: False,
#             RESP_ERROR: str(e)
#         }), HTTP_CONFLICT



@voting_bp.route('/ballots', methods=['GET'])
def get_ballots():
    # Get all ballots
    ballot_service = get_ballot_service()
    ballots = ballot_service.load_ballots()
    return jsonify({
        RESP_BALLOTS: ballots,
        RESP_TOTAL: len(ballots)
    })


# Verification end points

@voting_bp.route('/hashes', methods=['GET'])
def get_hashes():
    # Get all block hashes
    verification_service = get_verification_service()
    result = verification_service.get_status()
    
    if result[RESP_SUCCESS]:
        return jsonify({
            RESP_BLOCK_HASHES: result[RESP_BLOCK_HASHES],
            RESP_TOTAL_BLOCKS: result[RESP_TOTAL_BLOCKS]
        })
    else:
        return jsonify({RESP_ERROR: result[RESP_ERROR]}), 500

@voting_bp.route('/verify', methods=['GET'])
def verify():
    # Verify integrity of all blocks
    verification_service = get_verification_service()
    result = verification_service.verify_integrity()
    
    if result[RESP_SUCCESS]:
        return jsonify({
            RESP_VALID: result[RESP_VALID],
            RESP_BLOCKS_CHECKED: result[RESP_BLOCKS_CHECKED],
            RESP_RESULTS: result[RESP_RESULTS]
        })
    else:
        return jsonify({
            RESP_VALID: False,
            RESP_ERROR: result[RESP_ERROR]
        }), 500

@voting_bp.route('/blockchain-stats', methods=['GET'])
def blockchain_stats():
    # Get statistics about ballot store
    verification_service = get_verification_service()
    result = verification_service.get_status()
    
    if not result[RESP_SUCCESS]:
        return jsonify({RESP_ERROR: result[RESP_ERROR]}), 500
    
    # Verify integrity for status
    verify_result = verification_service.verify_integrity()
    integrity_status = "VALID" if verify_result.get(RESP_VALID, False) else "TAMPERED"
    if not verify_result[RESP_SUCCESS]:
        integrity_status = "ERROR"
    
    return jsonify({
        RESP_TOTAL_BALLOTS: result[RESP_TOTAL_BALLOTS],
        RESP_TOTAL_BLOCKS: result[RESP_TOTAL_BLOCKS],
        RESP_BLOCK_SIZE: result[RESP_BLOCK_SIZE],
        RESP_BALLOTS_IN_CURRENT: result[RESP_BALLOTS_IN_CURRENT],
        'integrity_status': integrity_status
    })


# Eligibility endpoints

@voting_bp.route('/voter/<voter_id>', methods=['GET'])
def lookup_voter(voter_id):
    """Lookup voter by ID and return division"""
    eligibility_service = get_eligibility_service()
    audit_service = get_audit_service()
    division, found = eligibility_service.lookup_voter(voter_id)
    
    if found:
        # ... Audit logging (as in original code) ...
        audit_service.log_data_access(
            user_id=get_user_id(),
            resource=f"/voter/{voter_id}",
            action='lookup',
            ip_address=get_client_ip(),
            result='found'
        )
        return jsonify({
            KEY_VOTER_ID: voter_id,
            KEY_DIVISION: division,
            KEY_STATUS: STATUS_FOUND
        }), HTTP_OK
    else:
        # Audit logging
        audit_service.log_data_access(
            user_id=get_user_id(),
            resource=f"/voter/{voter_id}",
            action='lookup',
            ip_address=get_client_ip(),
            result='not_found'
        )
        return jsonify({
            KEY_ERROR: 'Voter not found',
            KEY_VOTER_ID: voter_id,
            KEY_STATUS: STATUS_NOT_FOUND
        }), HTTP_NOT_FOUND

@voting_bp.route('/voter', methods=['GET'])
def lookup_voter_query():
    # Lookup voter by query parameter
    voter_id = request.args.get('id', '').strip()
    
    if not voter_id:
        return jsonify({
            KEY_ERROR: 'voter_id parameter required',
            KEY_STATUS: STATUS_BAD_REQUEST
        }), HTTP_BAD_REQUEST
    
    return lookup_voter(voter_id)

@voting_bp.route('/voter-stats', methods=['GET'])
def voter_stats():
    # Return statistics about the voter database
    eligibility_service = get_eligibility_service()
    total_voters = eligibility_service.get_total_voters()
    return jsonify({
        KEY_TOTAL_VOTERS: total_voters,
        KEY_STATUS: STATUS_OK
    }), HTTP_OK

@voting_bp.route('/reload-voters', methods=['POST'])
def reload_voters():
    # Reload voter data from files
    eligibility_service = get_eligibility_service()
    audit_service = get_audit_service()
    count = eligibility_service.reload_data()
    # Audit logging
    audit_service.log_system_event(
        "Voter data reloaded",
        total_voters=count
    )
    return jsonify({
        KEY_TOTAL_VOTERS: count,
        KEY_STATUS: STATUS_OK
    }), HTTP_OK


#Audit endpoints

@voting_bp.route('/login', methods=['POST'])
def login():
    #Login endpoint with authentication audit"""
    audit_service = get_audit_service()
    username = request.json.get('username') if request.json else None
    
    # Simulate authentication
    success = username and len(username) > 0
    
    # Log authentication event
    audit_service.log_authentication(
        user_id=username or 'unknown',
        success=success,
        ip_address=get_client_ip(),
        method='password'
    )
    
    return {'success': success}, HTTP_OK if success else 401

@voting_bp.route('/data/<resource_id>', methods=['GET'])
def get_data(resource_id):
    #Get data with access audit
    audit_service = get_audit_service()
    # Log data access
    audit_service.log_data_access(
        user_id=get_user_id(),
        resource=f"/data/{resource_id}",
        action='read',
        ip_address=get_client_ip(),
        resource_type='document'
    )
    
    return {'data': f'Resource {resource_id}'}

@voting_bp.route('/data/<resource_id>', methods=['PUT'])
def update_data(resource_id):
    #Update data with modification audit
    audit_service = get_audit_service()
    changes = request.json if request.json else {}
    
    # Log data modification
    audit_service.log_data_modification(
        user_id=get_user_id(),
        resource=f"/data/{resource_id}",
        action='update',
        ip_address=get_client_ip(),
        resource_type='document',
        changes=changes
    )
    
    return {'success': True}

@voting_bp.route('/verify-audit-log', methods=['GET'])
def verify_audit_log():
    #Endpoint to verify audit log integrity
    audit_service = get_audit_service()
    is_valid, message, count = audit_service.verify_integrity()
    
    return {
        'valid': is_valid,
        'message': message,
        'total_entries': count
    }

@voting_bp.route('/audit-stats', methods=['GET'])
def audit_stats():
    #Get audit log statistics
    audit_service = get_audit_service()
    stats = audit_service.get_statistics()
    return jsonify(stats)