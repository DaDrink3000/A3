# Ballot Keys
BALLOT_VOTER_ID = 'voter_id'
BALLOT_CHOICE = 'choice'

# Response Keys
RESP_SUCCESS = 'success'
RESP_ERROR = 'error'
RESP_BALLOT = 'ballot'
RESP_BALLOTS = 'ballots'
RESP_TOTAL = 'total'
RESP_TOTAL_BALLOTS = 'total_ballots'
RESP_BLOCK_HASHES = 'block_hashes'
RESP_TOTAL_BLOCKS = 'total_blocks'
RESP_VALID = 'valid'
RESP_BLOCKS_CHECKED = 'blocks_checked'
RESP_RESULTS = 'results'
RESP_BLOCK_SIZE = 'block_size'
RESP_BALLOTS_IN_CURRENT = 'ballots_in_current_block'

# Eligibility Keys
KEY_VOTER_ID = 'voter_id'
KEY_DIVISION = 'division'
KEY_STATUS = 'status'
KEY_ERROR = 'error'
KEY_TOTAL_VOTERS = 'total_voters'

# User Keys
KEY_USER_ID = 'user_id'
KEY_EMAIL = 'email'
KEY_FIRST_NAME = 'first_name'
KEY_SURNAME = 'surname'
KEY_ADDRESS = 'address'
KEY_DOB = 'dob'
KEY_MOBILE_NUMBER = 'mobile_number'
KEY_REGISTERED_AT = 'registered_at'

# Status Values
STATUS_FOUND = 'found'
STATUS_NOT_FOUND = 'not_found'
STATUS_BAD_REQUEST = 'bad_request'
STATUS_OK = 'ok'
STATUS_HEALTHY = 'healthy'
STATUS_CREATED = 'created'
STATUS_DUPLICATE = 'duplicate'

# HTTP status codes
HTTP_OK = 200
HTTP_CREATED = 201
HTTP_BAD_REQUEST = 400
HTTP_NOT_FOUND = 404
HTTP_CONFLICT = 409

# Event types
EVENT_REQUEST = "http_request"
EVENT_AUTH = "authentication"
EVENT_DATA_ACCESS = "data_access"
EVENT_DATA_MODIFY = "data_modification"
EVENT_ERROR = "error"
EVENT_SYSTEM = "system"
EVENT_USER_REGISTRATION = "user_registration"

# File paths
USERS_FILE = 'data/users.jsonl'