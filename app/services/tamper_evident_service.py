__all__ =['IntegrityException', 'BallotEvidentService' ]

import hashlib
import json
from datetime import datetime
import os
from portalocker import Lock
from contextlib import contextmanager


# Configuration
BLOCK_SIZE = 100
BALLOT_FILE = 'ballots.jsonl'
HASH_FILE = 'block_hashes.json'

# Ballot JSON Keys
BALLOT_ID = 'id'
BALLOT_VOTER_ID = 'voter_id'
BALLOT_CHOICE = 'choice'
BALLOT_TIMESTAMP = 'timestamp'

# Hash Entry JSON Keys
HASH_BLOCK_NUM = 'block_num'
HASH_START_ID = 'start_id'
HASH_END_ID = 'end_id'
HASH_VALUE = 'hash'
HASH_PREV = 'prev_hash'
HASH_TIMESTAMP = 'timestamp'

# Response JSON Keys
RESP_SUCCESS = 'success'
RESP_ERROR = 'error'
RESP_BALLOT = 'ballot'
RESP_VALID = 'valid'
RESP_STORED_HASH = 'stored_hash'
RESP_COMPUTED_HASH = 'computed_hash'


class IntegrityException(Exception):
    #Raised when ballot integrity is violated
    pass


class BallotEvidentService:
    def __init__(self):
        if not os.path.exists(BALLOT_FILE):
            open(BALLOT_FILE, 'w').close()
        if not os.path.exists(HASH_FILE):
            with open(HASH_FILE, 'w') as f:
                json.dump([], f)
    
    @contextmanager
    def file_lock(self, file_path):
        """
        Acquires an exclusive lock on a lock file associated with file_path.
        The lock is automatically released upon exiting the 'with' block.
        """
        # The lock file path remains the same
        lock_file_path = f"{file_path}.lock"
        
        # We use portalocker.Lock as a context manager
        # Mode 'w' creates the file if it doesn't exist
        lock = Lock(
            filename=lock_file_path,
            mode='w',
            timeout=5,  # Optional: Wait up to 5 seconds for the lock
            fail_when_locked=False, # Wait for the lock if busy
        )
        
        # When entering the 'with lock:', portalocker acquires the lock
        # When exiting the 'with lock:', portalocker releases the lock
        with lock:
            try:
                # Execution continues inside the 'with self.file_lock(..):' block
                yield
            except Exception as e:
                # Handle any exceptions that occur within the block
                raise e
            # No 'finally' needed for unlocking, as the 'with lock:' handles it.
    
    def compute_hash(self, data):
        return hashlib.sha256(data.encode()).hexdigest()
    
    def load_ballots(self):
        ballots = []
        if os.path.exists(BALLOT_FILE):
            with open(BALLOT_FILE, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        ballots.append(json.loads(line))
        return ballots
    
    def load_hashes(self):
        if os.path.exists(HASH_FILE):
            with open(HASH_FILE, 'r') as f:
                content = f.read().strip()
                if not content:
                    return []
                return json.loads(content)
        return []
    
    def save_hashes(self, hashes):
        with open(HASH_FILE, 'w') as f:
            json.dump(hashes, f, indent=2)
    
    def get_ballot_count(self):
        if os.path.exists(BALLOT_FILE):
            with open(BALLOT_FILE, 'r') as f:
                lines = f.readlines()
                if lines:
                    last_line = lines[-1].strip()
                    if last_line:
                        ballot = json.loads(last_line)
                        return ballot[BALLOT_ID]
        return 0
    
    def compute_block_hash(self, ballots, start_idx, end_idx, prev_hash='0'):
        block_data = []
        for i in range(start_idx, end_idx):
            if i < len(ballots):
                b = ballots[i]
                block_data.append(f"{b[BALLOT_ID]}|{b[BALLOT_VOTER_ID]}|{b[BALLOT_CHOICE]}|{b[BALLOT_TIMESTAMP]}")
        
        combined = prev_hash + '|' + '|'.join(block_data)
        return self.compute_hash(combined)
    
    def verify_integrity(self, raise_on_failure=False):
        ballots = self.load_ballots()
        block_hashes = self.load_hashes()
        results = []
        
        for hash_entry in block_hashes:
            start_idx = hash_entry[HASH_START_ID] - 1
            end_idx = hash_entry[HASH_END_ID]
            prev_hash = hash_entry[HASH_PREV]
            
            computed = self.compute_block_hash(ballots, start_idx, end_idx, prev_hash)
            stored = hash_entry[HASH_VALUE]
            
            is_valid = computed == stored
            
            results.append({
                HASH_BLOCK_NUM: hash_entry[HASH_BLOCK_NUM],
                RESP_VALID: is_valid,
                RESP_STORED_HASH: stored,
                RESP_COMPUTED_HASH: computed
            })
            
            if not is_valid and raise_on_failure:
                raise IntegrityException(
                    f"Block {hash_entry[HASH_BLOCK_NUM]} integrity violation! "
                    f"Expected: {stored}, Got: {computed}"
                )
        
        return results
    
    def verify_partial_block(self, ballots, block_hashes):
        if not block_hashes:
            return True
        
        total_complete_blocks = len(block_hashes)
        expected_next_id = total_complete_blocks * BLOCK_SIZE + 1
        
        for i, ballot in enumerate(ballots[total_complete_blocks * BLOCK_SIZE:]):
            if ballot[BALLOT_ID] != expected_next_id + i:
                raise IntegrityException(
                    f"Ballot ID mismatch in partial block! "
                    f"Expected: {expected_next_id + i}, Got: {ballot[BALLOT_ID]}"
                )
        
        return True
    
    def add_ballot(self, voter_id, choice):
        with self.file_lock(BALLOT_FILE):
            # Verify existing blocks
            try:
                self.verify_integrity(raise_on_failure=True)
            except IntegrityException as e:
                raise IntegrityException(f"Cannot add ballot - integrity violation detected: {str(e)}")
            
            # Load and verify partial block
            ballots = self.load_ballots()
            block_hashes = self.load_hashes()
            
            try:
                self.verify_partial_block(ballots, block_hashes)
            except IntegrityException as e:
                raise IntegrityException(f"Cannot add ballot - partial block tampered: {str(e)}")
            
            # Create new ballot
            ballot_id = self.get_ballot_count() + 1
            
            ballot = {
                BALLOT_ID: ballot_id,
                BALLOT_VOTER_ID: voter_id,
                BALLOT_CHOICE: choice,
                BALLOT_TIMESTAMP: datetime.utcnow().isoformat()
            }
            
            # Write ballot to disk
            with open(BALLOT_FILE, 'a') as f:
                f.write(json.dumps(ballot) + '\n')
                f.flush()
                os.fsync(f.fileno())
            
            # If block is complete, create hash
            if ballot_id % BLOCK_SIZE == 0:
                self.update_block_hash()
                """
                Re-verify integrity after creating new block hash
                This ensures the newly created hash is correct and detects
                any tampering that occurred during hash calculation
                """
                try:
                    self.verify_integrity(raise_on_failure=True)
                except IntegrityException as e:
                    raise IntegrityException(
                        f"Critical error: Block hash verification failed immediately after creation! "
                        f"Data may have been tampered during hash calculation. {str(e)}"
                    )
            
            return ballot
    
    def update_block_hash(self):
        """
        Creates a new block hash for the most recently completed block.
        Note: Caller MUST verify integrity after this method returns
        to ensure the hash was correctly calculated from untampered data.
        """
        ballots = self.load_ballots()
        block_hashes = self.load_hashes()
        
        block_num = len(ballots) // BLOCK_SIZE
        start_idx = (block_num - 1) * BLOCK_SIZE
        end_idx = block_num * BLOCK_SIZE
        
        prev_hash = block_hashes[-1][HASH_VALUE] if block_hashes else '0'
        block_hash = self.compute_block_hash(ballots, start_idx, end_idx, prev_hash)
        
        hash_entry = {
            HASH_BLOCK_NUM: block_num,
            HASH_START_ID: start_idx + 1,
            HASH_END_ID: end_idx,
            HASH_VALUE: block_hash,
            HASH_PREV: prev_hash,
            HASH_TIMESTAMP: datetime.utcnow().isoformat()
        }
        
        block_hashes.append(hash_entry)
        self.save_hashes(block_hashes)
        
        return hash_entry
