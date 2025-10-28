__all__ = ['BallotEvidentService', 'IntegrityException']
import json
import hashlib
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List
from logging.handlers import TimedRotatingFileHandler



class AuditLoggingService:
    """
    Tamper-evident audit logging service with blockchain-like hash chaining.
    Thread-safe and framework-agnostic.
    """
    
    # Event types
    EVENT_REQUEST = "http_request"
    EVENT_AUTH = "authentication"
    EVENT_DATA_ACCESS = "data_access"
    EVENT_DATA_MODIFY = "data_modification"
    EVENT_ERROR = "error"
    EVENT_SYSTEM = "system"
    EVENT_CUSTOM = "custom"
    
    # Log fields
    FIELD_TIMESTAMP = "timestamp"
    FIELD_EVENT_TYPE = "event_type"
    FIELD_USER_ID = "user_id"
    FIELD_IP_ADDRESS = "ip_address"
    FIELD_MESSAGE = "message"
    FIELD_HASH = "hash"
    FIELD_PREV_HASH = "prev_hash"
    
    def __init__(
        self,
        log_dir: str = "audit_logs",
        log_file: str = "audit.log",
        hash_algorithm: str = "sha256",
        rotation_when: str = "midnight",
        rotation_interval: int = 1,
        backup_count: int = 365,
        encoding: str = "utf-8"
    ):
       
        # Initialize the audit logging service.
        
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        self.log_path = self.log_dir / log_file
        self.index_path = self.log_dir / "audit_index.json"
        self.hash_algorithm = hash_algorithm
        self.encoding = encoding
        
        # Thread safety
        self._lock = threading.Lock()
        
        # Initialize state
        self.previous_hash = self._load_last_hash()
        
        # Setup logger
        self._setup_logger(rotation_when, rotation_interval, backup_count)
    
    def _setup_logger(self, rotation_when: str, rotation_interval: int, backup_count: int):
        """Setup rotating file handler with configurable rotation"""
        self.logger = logging.getLogger(f"audit_logger_{id(self)}")
        self.logger.setLevel(logging.INFO)
        self.logger.handlers.clear()
        self.logger.propagate = False
        
        handler = TimedRotatingFileHandler(
            filename=str(self.log_path),
            when=rotation_when,
            interval=rotation_interval,
            backupCount=backup_count,
            encoding=self.encoding
        )
        handler.suffix = "%d-%m-%Y"
        handler.setFormatter(logging.Formatter('%(message)s'))
        
        self.logger.addHandler(handler)
    
    def _compute_hash(self, data: Dict[str, Any]) -> str:
        """Compute hash of data using configured algorithm"""
        json_str = json.dumps(data, sort_keys=True)
        hash_func = getattr(hashlib, self.hash_algorithm)
        return hash_func(json_str.encode(self.encoding)).hexdigest()
    
    def _load_last_hash(self) -> Optional[str]:
        """Load the last hash from the index file"""
        if self.index_path.exists():
            try:
                with open(self.index_path, 'r', encoding=self.encoding) as f:
                    index = json.load(f)
                    return index.get('last_hash')
            except Exception:
                pass
        return None
    
    def _update_index(self, log_entry: Dict[str, Any]):
        """Update the index file with latest entry information"""
        try:
            entry_count = self._get_entry_count() + 1
            index = {
                'last_hash': log_entry[self.FIELD_HASH],
                'last_timestamp': log_entry[self.FIELD_TIMESTAMP],
                'total_entries': entry_count,
                'hash_algorithm': self.hash_algorithm
            }
            
            with open(self.index_path, 'w', encoding=self.encoding) as f:
                json.dump(index, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to update index: {e}")
    
    def _get_entry_count(self) -> int:
        """Get total number of entries from index"""
        if self.index_path.exists():
            try:
                with open(self.index_path, 'r', encoding=self.encoding) as f:
                    index = json.load(f)
                    return index.get('total_entries', 0)
            except Exception:
                pass
        return 0
    
    def log_event(
        self,
        event_type: str,
        message: str = "",
        user_id: str = "system",
        ip_address: str = "internal",
        **extra_data
    ) -> str:
        
        # Log an audit event with automatic hash chaining.
        
        with self._lock:
            log_entry = {
                self.FIELD_TIMESTAMP: datetime.utcnow().isoformat() + 'Z',
                self.FIELD_EVENT_TYPE: event_type,
                self.FIELD_USER_ID: user_id,
                self.FIELD_IP_ADDRESS: ip_address,
                self.FIELD_PREV_HASH: self.previous_hash,
            }
            
            if message:
                log_entry[self.FIELD_MESSAGE] = message
            
            # Add extra data
            log_entry.update(extra_data)
            
            # Compute hash
            log_entry[self.FIELD_HASH] = self._compute_hash(log_entry)
            
            # Write to log
            self.logger.info(json.dumps(log_entry))
            
            # Update index
            self._update_index(log_entry)
            
            # Update previous hash for next entry
            self.previous_hash = log_entry[self.FIELD_HASH]
            
            return log_entry[self.FIELD_HASH]
    
    def log_authentication(
        self,
        user_id: str,
        success: bool,
        ip_address: str = "unknown",
        method: str = "password",
        **extra_data
    ) -> str:
        #Log an authentication event
        return self.log_event(
            event_type=self.EVENT_AUTH,
            message=f"Authentication {'succeeded' if success else 'failed'}",
            user_id=user_id,
            ip_address=ip_address,
            success=success,
            auth_method=method,
            **extra_data
        )
    
    def log_data_access(
        self,
        user_id: str,
        resource: str,
        action: str = "read",
        ip_address: str = "unknown",
        **extra_data
    ) -> str:
        #Log a data access event
        return self.log_event(
            event_type=self.EVENT_DATA_ACCESS,
            message=f"User accessed resource: {resource}",
            user_id=user_id,
            ip_address=ip_address,
            resource=resource,
            action=action,
            **extra_data
        )
    
    def log_data_modification(
        self,
        user_id: str,
        resource: str,
        action: str = "update",
        ip_address: str = "unknown",
        **extra_data
    ) -> str:
        """Log a data modification event"""
        return self.log_event(
            event_type=self.EVENT_DATA_MODIFY,
            message=f"User modified resource: {resource}",
            user_id=user_id,
            ip_address=ip_address,
            resource=resource,
            action=action,
            **extra_data
        )
    
    def log_error(
        self,
        error_message: str,
        user_id: str = "system",
        ip_address: str = "internal",
        **extra_data
    ) -> str:
        #Log an error event"""
        return self.log_event(
            event_type=self.EVENT_ERROR,
            message=error_message,
            user_id=user_id,
            ip_address=ip_address,
            **extra_data
        )
    
    def log_system_event(
        self,
        message: str,
        **extra_data
    ) -> str:
        """Log a system event"""
        return self.log_event(
            event_type=self.EVENT_SYSTEM,
            message=message,
            user_id="system",
            ip_address="internal",
            **extra_data
        )
    
    def verify_integrity(
        self,
        log_file_path: Optional[str] = None
    ) -> Tuple[bool, str, int]:
        
        # Verify the integrity of the audit log by checking hash chain.
        
        
        if log_file_path is None:
            log_file_path = self.log_path
        
        log_path = Path(log_file_path)
        if not log_path.exists():
            return False, "Log file does not exist", 0
        
        previous_hash = None
        entry_count = 0
        
        try:
            with open(log_path, 'r', encoding=self.encoding) as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        entry = json.loads(line.strip())
                        entry_count += 1
                        
                        # Verify hash chain
                        if entry.get(self.FIELD_PREV_HASH) != previous_hash:
                            return False, f"Hash chain broken at line {line_num}", entry_count
                        
                        # Verify hash
                        recorded_hash = entry.pop(self.FIELD_HASH)
                        computed_hash = self._compute_hash(entry)
                        
                        if recorded_hash != computed_hash:
                            return False, f"Hash mismatch at line {line_num}", entry_count
                        
                        previous_hash = recorded_hash
                        
                    except json.JSONDecodeError:
                        return False, f"Invalid JSON at line {line_num}", entry_count
            
            return True, "Integrity verified", entry_count
            
        except Exception as e:
            return False, f"Error during verification: {str(e)}", entry_count
    
    def get_entries(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_type: Optional[str] = None,
        user_id: Optional[str] = None,
        limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        
        # Retrieve log entries matching filters.
      
       
        entries = []
        
        if not self.log_path.exists():
            return entries
        
        try:
            with open(self.log_path, 'r', encoding=self.encoding) as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        
                        # Apply filters
                        if start_time and datetime.fromisoformat(
                            entry[self.FIELD_TIMESTAMP].rstrip('Z')
                        ) < start_time:
                            continue
                        
                        if end_time and datetime.fromisoformat(
                            entry[self.FIELD_TIMESTAMP].rstrip('Z')
                        ) > end_time:
                            continue
                        
                        if event_type and entry.get(self.FIELD_EVENT_TYPE) != event_type:
                            continue
                        
                        if user_id and entry.get(self.FIELD_USER_ID) != user_id:
                            continue
                        
                        entries.append(entry)
                        
                        if limit and len(entries) >= limit:
                            break
                            
                    except (json.JSONDecodeError, KeyError):
                        continue
                        
        except Exception:
            pass
        
        return entries
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about the audit log"""
        stats = {
            'total_entries': self._get_entry_count(),
            'log_file': str(self.log_path),
            'log_size_bytes': self.log_path.stat().st_size if self.log_path.exists() else 0,
            'hash_algorithm': self.hash_algorithm,
        }
        
        if self.index_path.exists():
            try:
                with open(self.index_path, 'r', encoding=self.encoding) as f:
                    index = json.load(f)
                    stats['last_entry_time'] = index.get('last_timestamp')
            except Exception:
                pass
        
        return stats


# Example usage
if __name__ == "__main__":
    # Initialize the service
    audit_service = AuditLoggingService(
        log_dir="audit_logs",
        rotation_when="midnight",
        backup_count=365
    )
    
    # Log system startup
    audit_service.log_system_event(
        "Application started",
        version="1.0.0",
        environment="production"
    )
    
    # Log authentication
    audit_service.log_authentication(
        user_id="john.doe@example.com",
        success=True,
        ip_address="192.168.1.100",
        method="oauth2"
    )
    
    # Log data access
    audit_service.log_data_access(
        user_id="john.doe@example.com",
        resource="/api/users/123",
        action="read",
        ip_address="192.168.1.100"
    )
    
    # Log data modification
    audit_service.log_data_modification(
        user_id="john.doe@example.com",
        resource="/api/users/123",
        action="update",
        ip_address="192.168.1.100",
        changes={"email": "new@example.com"}
    )
    
    # Log error
    audit_service.log_error(
        error_message="Database connection failed",
        error_code="DB_CONNECTION_ERROR",
        severity="high"
    )
    
    # Verify integrity
    is_valid, message, count = audit_service.verify_integrity()
    print(f"Integrity check: {message} ({count} entries)")
    
    # Get statistics
    stats = audit_service.get_statistics()
    print(f"Audit log statistics: {stats}")