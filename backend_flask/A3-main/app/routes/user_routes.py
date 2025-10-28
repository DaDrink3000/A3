
from flask import Blueprint, request, jsonify, g
from datetime import datetime
import json
import os
from .constants import * # Assuming constants.py is in the same package
from .utils import (
    get_client_ip,
    get_user_id,
    load_all_users,
    check_user_exists,
    save_user,
    get_next_user_id
)

# Initialize Blueprint
user_bp = Blueprint('users', __name__)

def get_user_validation_service():
    
    from services import UserValidationService
    return UserValidationService(strict_mode=False, allow_international_mobile=True)

def get_audit_service():
    
    from services import AuditLoggingService
    return AuditLoggingService(log_dir="audit_logs", rotation_when="midnight", backup_count=365)
# -----------------------------------------------------------


@user_bp.route('/register', methods=['POST'])
def register_user():
    #Register a new user with validation"""
    user_validation_service = get_user_validation_service()
    audit_service = get_audit_service()
    
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({
            RESP_SUCCESS: False,
            RESP_ERROR: 'Invalid JSON in request body',
            KEY_STATUS: STATUS_BAD_REQUEST
        }), HTTP_BAD_REQUEST
    
    if not data:
        return jsonify({
            RESP_SUCCESS: False,
            RESP_ERROR: 'Request body is required',
            KEY_STATUS: STATUS_BAD_REQUEST
        }), HTTP_BAD_REQUEST
    
    # Validate user input
    validation_result = user_validation_service.validate_user(
        email=data.get(KEY_EMAIL),
        first_name=data.get(KEY_FIRST_NAME),
        surname=data.get(KEY_SURNAME),
        address=data.get(KEY_ADDRESS),
        dob=data.get(KEY_DOB),
        mobile_number=data.get(KEY_MOBILE_NUMBER),
        required_fields=[KEY_EMAIL, KEY_FIRST_NAME, KEY_SURNAME, KEY_DOB]
    )
    
    # Return validation errors if invalid
    if not validation_result.is_valid:
        #Audit logging
        audit_service.log_event(
            event_type=EVENT_USER_REGISTRATION,
            message="User registration failed - validation errors",
            user_id=get_user_id(),
            ip_address=get_client_ip(),
            success=False,
            validation_errors=validation_result.get_error_messages()
        )
        return jsonify({
            RESP_SUCCESS: False,
            RESP_ERROR: 'Validation failed',
            'validation_errors': validation_result.to_dict(),
            KEY_STATUS: STATUS_BAD_REQUEST
        }), HTTP_BAD_REQUEST
    
    sanitized_data = validation_result.sanitized_data
    
    # Check for duplicate email
    if check_user_exists(sanitized_data[KEY_EMAIL]):
        #Audit logging
        audit_service.log_event(
            event_type=EVENT_USER_REGISTRATION,
            message="User registration failed - duplicate email",
            user_id=get_user_id(),
            ip_address=get_client_ip(),
            success=False,
            email=sanitized_data[KEY_EMAIL]
        )
        return jsonify({
            RESP_SUCCESS: False,
            RESP_ERROR: 'User with this email already exists',
            KEY_STATUS: STATUS_DUPLICATE
        }), HTTP_CONFLICT
    
    # Create user record
    user_id = get_next_user_id()
    user_record = {
        KEY_USER_ID: user_id,
        KEY_EMAIL: sanitized_data[KEY_EMAIL],
        KEY_FIRST_NAME: sanitized_data[KEY_FIRST_NAME],
        KEY_SURNAME: sanitized_data[KEY_SURNAME],
        KEY_ADDRESS: sanitized_data.get(KEY_ADDRESS),
        KEY_DOB: sanitized_data[KEY_DOB],
        KEY_MOBILE_NUMBER: sanitized_data.get(KEY_MOBILE_NUMBER),
        KEY_REGISTERED_AT: datetime.utcnow().isoformat() + 'Z'
    }
    
    # Save user
    try:
        save_user(user_record)
        
        #Audit logging
        audit_service.log_event(
            event_type=EVENT_USER_REGISTRATION,
            message=f"User registered successfully",
            user_id=get_user_id(),
            ip_address=get_client_ip(),
            success=True,
            new_user_id=user_id,
            email=user_record[KEY_EMAIL]
        )
        
        response_data = user_record.copy()
        
        return jsonify({
            RESP_SUCCESS: True,
            'user': response_data,
            KEY_STATUS: STATUS_CREATED,
            'message': 'User registered successfully'
        }), HTTP_CREATED
        
    except Exception as e:
        # Error logging
        audit_service.log_error(
            error_message=f"Failed to save user: {str(e)}",
            user_id=get_user_id(),
            ip_address=get_client_ip(),
            error_type=type(e).__name__
        )
        
        return jsonify({
            RESP_SUCCESS: False,
            RESP_ERROR: 'Failed to register user',
            KEY_STATUS: STATUS_BAD_REQUEST
        }), HTTP_BAD_REQUEST

@user_bp.route('/users', methods=['GET'])
def get_users():
    #Get all registered users
    audit_service = get_audit_service()
    try:
        users = load_all_users()
        # Audit logging
        audit_service.log_data_access(
            user_id=get_user_id(),
            resource='/users',
            action='list',
            ip_address=get_client_ip(),
            result='success',
            count=len(users)
        )
        
        return jsonify({
            RESP_SUCCESS: True,
            'users': users,
            RESP_TOTAL: len(users)
        }), HTTP_OK
        
    except Exception as e:
        # Error logging
        audit_service.log_error(
            error_message=f"Failed to load users: {str(e)}",
            user_id=get_user_id(),
            ip_address=get_client_ip()
        )
        
        return jsonify({
            RESP_SUCCESS: False,
            RESP_ERROR: 'Failed to load users'
        }), 500

@user_bp.route('/user/<int:user_id>', methods=['GET'])
def get_user(user_id):
    #Get user by ID
    audit_service = get_audit_service()
    try:
        users = load_all_users()
        user = next((u for u in users if u.get(KEY_USER_ID) == user_id), None)
        
        if not user:
            #Audit logging
            audit_service.log_data_access(
                user_id=get_user_id(),
                resource=f'/user/{user_id}',
                action='read',
                ip_address=get_client_ip(),
                result='not_found'
            )
            
            return jsonify({
                RESP_SUCCESS: False,
                RESP_ERROR: 'User not found',
                KEY_STATUS: STATUS_NOT_FOUND
            }), HTTP_NOT_FOUND
        
        # Audit logging
        audit_service.log_data_access(
            user_id=get_user_id(),
            resource=f'/user/{user_id}',
            action='read',
            ip_address=get_client_ip(),
            result='success'
        )
        
        return jsonify({
            RESP_SUCCESS: True,
            'user': user,
            KEY_STATUS: STATUS_FOUND
        }), HTTP_OK
        
    except Exception as e:
        # Error logging
        audit_service.log_error(
            error_message=f"Failed to load user: {str(e)}",
            user_id=get_user_id(),
            ip_address=get_client_ip()
        )
        
        return jsonify({
            RESP_SUCCESS: False,
            RESP_ERROR: 'Failed to load user'
        }), 500

@user_bp.route('/user/email/<email>', methods=['GET'])
def get_user_by_email(email):
    #Get user by email
    audit_service = get_audit_service()
    try:
        users = load_all_users()
        user = next((u for u in users if u.get(KEY_EMAIL, '').lower() == email.lower()), None)
        
        if not user:
            return jsonify({
                RESP_SUCCESS: False,
                RESP_ERROR: 'User not found',
                KEY_STATUS: STATUS_NOT_FOUND
            }), HTTP_NOT_FOUND
        
        # Audit logging
        audit_service.log_data_access(
            user_id=get_user_id(),
            resource=f'/user/email/{email}',
            action='read',
            ip_address=get_client_ip(),
            result='success'
        )
        
        return jsonify({
            RESP_SUCCESS: True,
            'user': user,
            KEY_STATUS: STATUS_FOUND
        }), HTTP_OK
        
    except Exception:
        return jsonify({
            RESP_SUCCESS: False,
            RESP_ERROR: 'Failed to load user'
        }), 500