
__all__ = ['BlockchainVerificationService']

import hashlib
import json
import os
from typing import List, Dict, Any

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
RESP_BLOCK_HASHES = 'block_hashes'
RESP_TOTAL_BLOCKS = 'total_blocks'
RESP_VALID = 'valid'
RESP_BLOCKS_CHECKED = 'blocks_checked'
RESP_RESULTS = 'results'
RESP_TOTAL_BALLOTS = 'total_ballots'
RESP_BLOCK_SIZE = 'block_size'
RESP_BALLOTS_IN_CURRENT = 'ballots_in_current_block'
RESP_STORED_HASH = 'stored_hash'
RESP_COMPUTED_HASH = 'computed_hash'


class BlockchainVerificationService:
    """Service for verifying blockchain integrity of voting ballots"""
    
    def __init__(self, ballot_file: str = BALLOT_FILE, hash_file: str = HASH_FILE, block_size: int = BLOCK_SIZE):
        
        # Initialize the verification service
        
        
        self.ballot_file = ballot_file
        self.hash_file = hash_file
        self.block_size = block_size
    
    @staticmethod
    def compute_hash(data: str) -> str:
        #Compute SHA-256 hash
        return hashlib.sha256(data.encode()).hexdigest()
    
    def load_ballots(self) -> List[Dict[str, Any]]:
        """Load all ballots from file"""
        ballots = []
        if os.path.exists(self.ballot_file):
            with open(self.ballot_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        ballots.append(json.loads(line))
        return ballots
    
    def load_hashes(self) -> List[Dict[str, Any]]:
        """Load block hashes from file"""
        if os.path.exists(self.hash_file):
            with open(self.hash_file, 'r') as f:
                return json.load(f)
        return []
    
    def get_ballot_count(self) -> int:
        #Get total number of ballots
        if os.path.exists(self.ballot_file):
            with open(self.ballot_file, 'r') as f:
                lines = f.readlines()
                if lines:
                    last_line = lines[-1].strip()
                    if last_line:
                        ballot = json.loads(last_line)
                        return ballot[BALLOT_ID]
        return 0
    
    def compute_block_hash(self, ballots: List[Dict[str, Any]], start_idx: int, end_idx: int, prev_hash: str = '0') -> str:
        
        # Compute hash for a block of ballots
        
        block_data = []
        for i in range(start_idx, end_idx):
            if i < len(ballots):
                b = ballots[i]
                block_data.append(f"{b[BALLOT_ID]}|{b[BALLOT_VOTER_ID]}|{b[BALLOT_CHOICE]}|{b[BALLOT_TIMESTAMP]}")
        
        combined = prev_hash + '|' + '|'.join(block_data)
        return self.compute_hash(combined)
    
    def verify_integrity(self) -> Dict[str, Any]:
        
        # Verify integrity of all blocks
        
    
        try:
            ballots = self.load_ballots()
            block_hashes = self.load_hashes()
            results = []
            all_valid = True
            
            for hash_entry in block_hashes:
                start_idx = hash_entry[HASH_START_ID] - 1
                end_idx = hash_entry[HASH_END_ID]
                prev_hash = hash_entry[HASH_PREV]
                
                computed = self.compute_block_hash(ballots, start_idx, end_idx, prev_hash)
                stored = hash_entry[HASH_VALUE]
                is_valid = computed == stored
                
                if not is_valid:
                    all_valid = False
                
                results.append({
                    HASH_BLOCK_NUM: hash_entry[HASH_BLOCK_NUM],
                    HASH_START_ID: hash_entry[HASH_START_ID],
                    HASH_END_ID: hash_entry[HASH_END_ID],
                    RESP_VALID: is_valid,
                    RESP_STORED_HASH: stored,
                    RESP_COMPUTED_HASH: computed
                })
            
            return {
                RESP_SUCCESS: True,
                RESP_VALID: all_valid,
                RESP_BLOCKS_CHECKED: len(results),
                RESP_TOTAL_BALLOTS: len(ballots),
                RESP_RESULTS: results
            }
            
        except Exception as e:
            return {
                RESP_SUCCESS: False,
                RESP_ERROR: str(e)
            }
    
    def verify_single_block(self, block_num: int) -> Dict[str, Any]:
        
        # Verify integrity of a single block
        
    
        try:
            ballots = self.load_ballots()
            block_hashes = self.load_hashes()
            
            hash_entry = next((h for h in block_hashes if h[HASH_BLOCK_NUM] == block_num), None)
            
            if not hash_entry:
                return {
                    RESP_SUCCESS: False,
                    RESP_ERROR: f"Block {block_num} not found"
                }
            
            start_idx = hash_entry[HASH_START_ID] - 1
            end_idx = hash_entry[HASH_END_ID]
            prev_hash = hash_entry[HASH_PREV]
            
            computed = self.compute_block_hash(ballots, start_idx, end_idx, prev_hash)
            stored = hash_entry[HASH_VALUE]
            is_valid = computed == stored
            
            return {
                RESP_SUCCESS: True,
                HASH_BLOCK_NUM: block_num,
                HASH_START_ID: hash_entry[HASH_START_ID],
                HASH_END_ID: hash_entry[HASH_END_ID],
                RESP_VALID: is_valid,
                RESP_STORED_HASH: stored,
                RESP_COMPUTED_HASH: computed
            }
            
        except Exception as e:
            return {
                RESP_SUCCESS: False,
                RESP_ERROR: str(e)
            }
    
    def get_status(self) -> Dict[str, Any]:
        
        # Get current blockchain status
        
        
        try:
            ballot_count = self.get_ballot_count()
            block_hashes = self.load_hashes()
            ballots_in_current = ballot_count % self.block_size if ballot_count % self.block_size != 0 else self.block_size
            
            return {
                RESP_SUCCESS: True,
                RESP_TOTAL_BALLOTS: ballot_count,
                RESP_TOTAL_BLOCKS: len(block_hashes),
                RESP_BLOCK_SIZE: self.block_size,
                RESP_BALLOTS_IN_CURRENT: ballots_in_current,
                RESP_BLOCK_HASHES: block_hashes
            }
            
        except Exception as e:
            return {
                RESP_SUCCESS: False,
                RESP_ERROR: str(e)
            }