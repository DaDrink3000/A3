__all__ =['UserValidationService', 'ValidationSeverity', 'ValidationError', 'ValidationResult']

import re
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum



# Constant and configuration


# Validation constraints
MIN_NAME_LENGTH = 2
MAX_NAME_LENGTH = 50
MIN_ADDRESS_LENGTH = 5
MAX_ADDRESS_LENGTH = 200
MIN_AGE = 13
MAX_AGE = 120
MOBILE_MIN_LENGTH = 10
MOBILE_MAX_LENGTH = 15

# Regex patterns
EMAIL_PATTERN = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
NAME_PATTERN = r'^[a-zA-Z\s\'-]+$'
MOBILE_PATTERN = r'^\+?[0-9\s\-\(\)]+$'

# Date formats to try
DATE_FORMATS = [
    '%d-%m-%Y',
]

# Error messages
ERROR_REQUIRED = "is required"
ERROR_INVALID_FORMAT = "has invalid format"
ERROR_TOO_SHORT = "is too short"
ERROR_TOO_LONG = "is too long"
ERROR_INVALID_AGE = "age must be between {min} and {max} years"
ERROR_FUTURE_DATE = "date cannot be in the future"
ERROR_INVALID_CHARS = "contains invalid characters"
ERROR_INVALID_EMAIL = "is not a valid email address"
ERROR_INVALID_MOBILE = "is not a valid mobile number"



# Validation result classes


class ValidationSeverity(Enum):
    """Severity levels for validation errors"""
    ERROR = "error"
    WARNING = "warning"


@dataclass
class ValidationError:
    #Represents a single validation error
    field: str
    message: str
    severity: ValidationSeverity = ValidationSeverity.ERROR
    code: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'field': self.field,
            'message': self.message,
            'severity': self.severity.value,
            'code': self.code
        }


@dataclass
class ValidationResult:
    #Result of validation operation"""
    is_valid: bool
    errors: List[ValidationError]
    warnings: List[ValidationError]
    sanitized_data: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'is_valid': self.is_valid,
            'errors': [e.to_dict() for e in self.errors],
            'warnings': [w.to_dict() for w in self.warnings],
            'sanitized_data': self.sanitized_data
        }
    
    def has_errors(self) -> bool:
        return len(self.errors) > 0
    
    def get_error_messages(self) -> List[str]:
        return [f"{e.field}: {e.message}" for e in self.errors]



# User validation service 


class UserValidationService:
    """
    Comprehensive user input validation service.
    Validates email, names, address, date of birth, and mobile number.
    """
    
    def __init__(
        self,
        strict_mode: bool = False,
        allow_international_mobile: bool = True
    ):
        
        # Initialize validation service
        
    
        self.strict_mode = strict_mode
        self.allow_international_mobile = allow_international_mobile
    
    
    # Main validation method
    
    
    def validate_user(
        self,
        email: Optional[str] = None,
        first_name: Optional[str] = None,
        surname: Optional[str] = None,
        address: Optional[str] = None,
        dob: Optional[str] = None,
        mobile_number: Optional[str] = None,
        required_fields: Optional[List[str]] = None
    ) -> ValidationResult:
        
        #Validate all user fields
        
        errors = []
        warnings = []
        sanitized = {}
        
        if required_fields is None:
            required_fields = []
        
        # Validate email
        if 'email' in required_fields or email:
            result = self.validate_email(email, required='email' in required_fields)
            errors.extend(result['errors'])
            warnings.extend(result['warnings'])
            if result['value']:
                sanitized['email'] = result['value']
        
        # Validate first name
        if 'first_name' in required_fields or first_name:
            result = self.validate_name(
                first_name, 
                'first_name',
                required='first_name' in required_fields
            )
            errors.extend(result['errors'])
            warnings.extend(result['warnings'])
            if result['value']:
                sanitized['first_name'] = result['value']
        
        # Validate surname
        if 'surname' in required_fields or surname:
            result = self.validate_name(
                surname,
                'surname',
                required='surname' in required_fields
            )
            errors.extend(result['errors'])
            warnings.extend(result['warnings'])
            if result['value']:
                sanitized['surname'] = result['value']
        
        # Validate address
        if 'address' in required_fields or address:
            result = self.validate_address(
                address,
                required='address' in required_fields
            )
            errors.extend(result['errors'])
            warnings.extend(result['warnings'])
            if result['value']:
                sanitized['address'] = result['value']
        
        # Validate date of birth
        if 'dob' in required_fields or dob:
            result = self.validate_dob(dob, required='dob' in required_fields)
            errors.extend(result['errors'])
            warnings.extend(result['warnings'])
            if result['value']:
                sanitized['dob'] = result['value']
        
        # Validate mobile number
        if 'mobile_number' in required_fields or mobile_number:
            result = self.validate_mobile_number(
                mobile_number,
                required='mobile_number' in required_fields
            )
            errors.extend(result['errors'])
            warnings.extend(result['warnings'])
            if result['value']:
                sanitized['mobile_number'] = result['value']
        
        is_valid = len(errors) == 0
        
        return ValidationResult(
            is_valid=is_valid,
            errors=errors,
            warnings=warnings,
            sanitized_data=sanitized if is_valid else None
        )
    
    
    # Individual field validators
    
    
    def validate_email(
        self,
        email: Optional[str],
        required: bool = False
    ) -> Dict[str, Any]:
        # Validate email address
        errors = []
        warnings = []
        
        if not email or not email.strip():
            if required:
                errors.append(ValidationError(
                    field='email',
                    message=f"Email {ERROR_REQUIRED}",
                    code='EMAIL_REQUIRED'
                ))
            return {'errors': errors, 'warnings': warnings, 'value': None}
        
        email = email.strip().lower()
        
        # Check format
        if not re.match(EMAIL_PATTERN, email):
            errors.append(ValidationError(
                field='email',
                message=ERROR_INVALID_EMAIL,
                code='EMAIL_INVALID_FORMAT'
            ))
            return {'errors': errors, 'warnings': warnings, 'value': None}
        
        # Check length
        if len(email) > 254:  # RFC 5321
            errors.append(ValidationError(
                field='email',
                message=f"Email {ERROR_TOO_LONG} (max 254 characters)",
                code='EMAIL_TOO_LONG'
            ))
        
        # Warnings for suspicious patterns
        if email.count('@') > 1:
            warnings.append(ValidationError(
                field='email',
                message="Email contains multiple @ symbols",
                severity=ValidationSeverity.WARNING,
                code='EMAIL_SUSPICIOUS'
            ))
        
        if '..' in email:
            warnings.append(ValidationError(
                field='email',
                message="Email contains consecutive dots",
                severity=ValidationSeverity.WARNING,
                code='EMAIL_SUSPICIOUS'
            ))
        
        return {
            'errors': errors,
            'warnings': warnings,
            'value': email if not errors else None
        }
    
    def validate_name(
        self,
        name: Optional[str],
        field_name: str = 'name',
        required: bool = False
    ) -> Dict[str, Any]:
        """Validate first name or surname"""
        errors = []
        warnings = []
        
        if not name or not name.strip():
            if required:
                errors.append(ValidationError(
                    field=field_name,
                    message=f"{field_name.replace('_', ' ').title()} {ERROR_REQUIRED}",
                    code=f"{field_name.upper()}_REQUIRED"
                ))
            return {'errors': errors, 'warnings': warnings, 'value': None}
        
        name = name.strip()
        
        # Check length
        if len(name) < MIN_NAME_LENGTH:
            errors.append(ValidationError(
                field=field_name,
                message=f"{field_name.replace('_', ' ').title()} {ERROR_TOO_SHORT} (min {MIN_NAME_LENGTH} characters)",
                code=f"{field_name.upper()}_TOO_SHORT"
            ))
        
        if len(name) > MAX_NAME_LENGTH:
            errors.append(ValidationError(
                field=field_name,
                message=f"{field_name.replace('_', ' ').title()} {ERROR_TOO_LONG} (max {MAX_NAME_LENGTH} characters)",
                code=f"{field_name.upper()}_TOO_LONG"
            ))
        
        # Check for valid characters
        if not re.match(NAME_PATTERN, name):
            errors.append(ValidationError(
                field=field_name,
                message=f"{field_name.replace('_', ' ').title()} {ERROR_INVALID_CHARS}",
                code=f"{field_name.upper()}_INVALID_CHARS"
            ))
        
        # Check for numbers
        if any(char.isdigit() for char in name):
            errors.append(ValidationError(
                field=field_name,
                message=f"{field_name.replace('_', ' ').title()} cannot contain numbers",
                code=f"{field_name.upper()}_HAS_NUMBERS"
            ))
        
        # Warnings
        if self.strict_mode and not name[0].isupper():
            warnings.append(ValidationError(
                field=field_name,
                message=f"{field_name.replace('_', ' ').title()} should start with capital letter",
                severity=ValidationSeverity.WARNING,
                code=f"{field_name.upper()}_CAPITALIZATION"
            ))
        
        # Sanitize: Title case
        sanitized_name = name.title() if not errors else None
        
        return {
            'errors': errors,
            'warnings': warnings,
            'value': sanitized_name
        }
    
    def validate_address(
        self,
        address: Optional[str],
        required: bool = False
    ) -> Dict[str, Any]:
        """Validate physical address"""
        errors = []
        warnings = []
        
        if not address or not address.strip():
            if required:
                errors.append(ValidationError(
                    field='address',
                    message=f"Address {ERROR_REQUIRED}",
                    code='ADDRESS_REQUIRED'
                ))
            return {'errors': errors, 'warnings': warnings, 'value': None}
        
        address = address.strip()
        
        # Check length
        if len(address) < MIN_ADDRESS_LENGTH:
            errors.append(ValidationError(
                field='address',
                message=f"Address {ERROR_TOO_SHORT} (min {MIN_ADDRESS_LENGTH} characters)",
                code='ADDRESS_TOO_SHORT'
            ))
        
        if len(address) > MAX_ADDRESS_LENGTH:
            errors.append(ValidationError(
                field='address',
                message=f"Address {ERROR_TOO_LONG} (max {MAX_ADDRESS_LENGTH} characters)",
                code='ADDRESS_TOO_LONG'
            ))
        
        # Sanitize: Remove extra whitespace
        sanitized_address = ' '.join(address.split()) if not errors else None
        
        return {
            'errors': errors,
            'warnings': warnings,
            'value': sanitized_address
        }
    
    def validate_dob(
        self,
        dob: Optional[str],
        required: bool = False
    ) -> Dict[str, Any]:
        """Validate date of birth"""
        errors = []
        warnings = []
        
        if not dob or not str(dob).strip():
            if required:
                errors.append(ValidationError(
                    field='dob',
                    message=f"Date of birth {ERROR_REQUIRED}",
                    code='DOB_REQUIRED'
                ))
            return {'errors': errors, 'warnings': warnings, 'value': None}
        
        dob_str = str(dob).strip()
        parsed_date = None
        
        # Try to parse date
        for date_format in DATE_FORMATS:
            try:
                parsed_date = datetime.strptime(dob_str, date_format)
                break
            except ValueError:
                continue
        
        if not parsed_date:
            errors.append(ValidationError(
                field='dob',
                message=f"Date of birth {ERROR_INVALID_FORMAT}. Expected formats: YYYY-MM-DD, DD/MM/YYYY, etc.",
                code='DOB_INVALID_FORMAT'
            ))
            return {'errors': errors, 'warnings': warnings, 'value': None}
        
        # Check if date is in the future
        if parsed_date > datetime.now():
            errors.append(ValidationError(
                field='dob',
                message=f"Date of birth {ERROR_FUTURE_DATE}",
                code='DOB_FUTURE_DATE'
            ))
        
        # Calculate age
        today = datetime.now()
        age = today.year - parsed_date.year - (
            (today.month, today.day) < (parsed_date.month, parsed_date.day)
        )
        
        # Check age range
        if age < MIN_AGE:
            errors.append(ValidationError(
                field='dob',
                message=ERROR_INVALID_AGE.format(min=MIN_AGE, max=MAX_AGE),
                code='DOB_TOO_YOUNG'
            ))
        
        if age > MAX_AGE:
            errors.append(ValidationError(
                field='dob',
                message=ERROR_INVALID_AGE.format(min=MIN_AGE, max=MAX_AGE),
                code='DOB_TOO_OLD'
            ))
        
        # Return ISO format date string
        sanitized_dob = parsed_date.strftime('%d-%m-%Y') if not errors else None
        
        return {
            'errors': errors,
            'warnings': warnings,
            'value': sanitized_dob
        }
    
    def validate_mobile_number(
        self,
        mobile: Optional[str],
        required: bool = False
    ) -> Dict[str, Any]:
        #Validate mobile phone number
        errors = []
        warnings = []
        
        if not mobile or not str(mobile).strip():
            if required:
                errors.append(ValidationError(
                    field='mobile_number',
                    message=f"Mobile number {ERROR_REQUIRED}",
                    code='MOBILE_REQUIRED'
                ))
            return {'errors': errors, 'warnings': warnings, 'value': None}
        
        mobile = str(mobile).strip()
        
        # Check basic format
        if not re.match(MOBILE_PATTERN, mobile):
            errors.append(ValidationError(
                field='mobile_number',
                message=ERROR_INVALID_MOBILE,
                code='MOBILE_INVALID_FORMAT'
            ))
            return {'errors': errors, 'warnings': warnings, 'value': None}
        
        # Remove formatting characters for length check
        digits_only = re.sub(r'[^\d]', '', mobile)
        
        # Check length
        if len(digits_only) < MOBILE_MIN_LENGTH:
            errors.append(ValidationError(
                field='mobile_number',
                message=f"Mobile number {ERROR_TOO_SHORT} (min {MOBILE_MIN_LENGTH} digits)",
                code='MOBILE_TOO_SHORT'
            ))
        
        if len(digits_only) > MOBILE_MAX_LENGTH:
            errors.append(ValidationError(
                field='mobile_number',
                message=f"Mobile number {ERROR_TOO_LONG} (max {MOBILE_MAX_LENGTH} digits)",
                code='MOBILE_TOO_LONG'
            ))
        
        # Warning for international format
        if not self.allow_international_mobile and mobile.startswith('+'):
            warnings.append(ValidationError(
                field='mobile_number',
                message="International format detected",
                severity=ValidationSeverity.WARNING,
                code='MOBILE_INTERNATIONAL'
            ))
        
        # Sanitize: Keep only digits and + for international
        if self.allow_international_mobile:
            sanitized_mobile = re.sub(r'[^\d+]', '', mobile)
        else:
            sanitized_mobile = digits_only
        
        sanitized_mobile = sanitized_mobile if not errors else None
        
        return {
            'errors': errors,
            'warnings': warnings,
            'value': sanitized_mobile
        }

