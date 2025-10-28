from flask import request, g
import os
import json
from .constants import USERS_FILE

# User Storage Helpers

def ensure_data_directory():
    # Ensure data directory exists
    os.makedirs('data', exist_ok=True)

def load_all_users():
    #Load all users from file
    ensure_data_directory()
    users = []
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    users.append(json.loads(line))
    return users

def check_user_exists(email):
    #Check if user with email already exists
    users = load_all_users()
    return any(u.get('email', '').lower() == email.lower() for u in users)

def save_user(user_data):
    # Save user to file
    ensure_data_directory()
    with open(USERS_FILE, 'a') as f:
        f.write(json.dumps(user_data) + '\n')
        f.flush()
        os.fsync(f.fileno())

def get_next_user_id():
    # Get next user ID
    users = load_all_users()
    if not users:
        return 1
    return max(u.get('user_id', 0) for u in users) + 1

# Audit Helpers

def get_client_ip():
    # Get client IP address from request
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr or 'unknown'

def get_user_id():
    # Get user ID from request context
    return getattr(g, 'user_id', 'anonymous')