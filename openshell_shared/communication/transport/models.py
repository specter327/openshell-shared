# Library import
from enum import Enum

# Classes definition
class CONNECTION_STATUS(str, Enum):
	OPEN = "OPEN"
	CLOSED = "CLOSED"
	LISTENING = "LISTENING"