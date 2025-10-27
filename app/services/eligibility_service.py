__all__ = ['EligibilityService']


import json
import csv
import logging
import os


# Constants and configuration

# File paths
DATA_FILE_JSON = '../data/voters.json'
DATA_FILE_CSV = '../data/voters.csv'
LOG_FILE = './logs/voter_lookups.log'

# CSV/JSON column names
COLUMN_VOTER_ID = 'voter_id'
COLUMN_DIVISION = 'division'

# API Configuration
API_HOST = '0.0.0.0'
API_PORT = 5001
API_DEBUG = True

# HTTP Status codes
HTTP_OK = 200
HTTP_BAD_REQUEST = 400
HTTP_NOT_FOUND = 404

# Response keys
KEY_VOTER_ID = 'voter_id'
KEY_DIVISION = 'division'
KEY_STATUS = 'status'
KEY_ERROR = 'error'
KEY_TOTAL_VOTERS = 'total_voters'

# Status values
STATUS_FOUND = 'found'
STATUS_NOT_FOUND = 'not_found'
STATUS_BAD_REQUEST = 'bad_request'
STATUS_OK = 'ok'
STATUS_HEALTHY = 'healthy'

# Logging
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
LOG_LEVEL = logging.INFO


# Eligibility service class

class EligibilityService:
    # Service class for managing voter eligibility data and lookups
    
    def __init__(self, json_filepath=DATA_FILE_JSON, csv_filepath=DATA_FILE_CSV, log_file=LOG_FILE):
        # Initialize the eligibility service
        self.json_filepath = json_filepath
        self.csv_filepath = csv_filepath
        self.voters_db = {}
        
        # Configure logging
        logging.basicConfig(
            level=LOG_LEVEL,
            format=LOG_FORMAT,
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Load data on initialization
        self._load_data()
    
    def _load_data(self):
        # Load voter data from available data sources
        if os.path.exists(self.json_filepath):
            self._load_json_data(self.json_filepath)
        elif os.path.exists(self.csv_filepath):
            self._load_csv_data(self.csv_filepath)
        else:
            self.logger.warning(
                f"No voter data file found. Please add {self.json_filepath} or {self.csv_filepath}"
            )
    
    def _load_json_data(self, filepath):
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                for voter in data:
                    voter_id = str(voter.get(COLUMN_VOTER_ID, '')).strip().lower()
                    if voter_id:
                        self.voters_db[voter_id] = voter.get(COLUMN_DIVISION, 'Unknown')
                self.logger.info(f"Loaded {len(self.voters_db)} voters from JSON: {filepath}")
        except Exception as e:
            self.logger.error(f"Error loading JSON file: {e}")
    
    def _load_csv_data(self, filepath):
        try:
            with open(filepath, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    voter_id = str(row.get(COLUMN_VOTER_ID, '')).strip().lower()
                    if voter_id:
                        self.voters_db[voter_id] = row.get(COLUMN_DIVISION, 'Unknown')
                self.logger.info(f"Loaded {len(self.voters_db)} voters from CSV: {filepath}")
        except Exception as e:
            self.logger.error(f"Error loading CSV file: {e}")
    
    def lookup_voter(self, voter_id):
        if not voter_id:
            return None, False
        
        normalized_id = str(voter_id).strip().lower()
        self.logger.info(f"Lookup request for voter_id: {normalized_id}")
        
        if normalized_id in self.voters_db:
            division = self.voters_db[normalized_id]
            self.logger.info(f"Voter {normalized_id} found in division: {division}")
            return division, True
        else:
            self.logger.info(f"Voter {normalized_id} not found")
            return None, False
    
    def get_total_voters(self):
        # Get the total number of voters in the database
        return len(self.voters_db)
    
    def reload_data(self):
        #Reload voter data from files
        self.voters_db = {}
        self._load_data()
        return len(self.voters_db)
