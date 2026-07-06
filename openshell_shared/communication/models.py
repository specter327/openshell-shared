# Library import
from enum import Enum

class RoleType(str, Enum):
	SERVER: str = "SERVER"
	CLIENT: str = "CLIENT"

	CLIENT_SERVER: str = "CLIENT/SERVER"