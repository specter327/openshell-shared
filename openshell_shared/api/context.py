# Library import
from typing import Dict

# Classes definition
class ContextManager:
	def __init__(self):
		self.local_auth: Dict[str, Dict] = {}
		self.remote_auth: Dict[str, Dict] = {}

		self.sessions: Dict[str, Dict] = {}