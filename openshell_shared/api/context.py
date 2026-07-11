# Library import
from typing import Dict

# Classes definition
class ContextManager:
	def __init__(self):
		self.local_auth: Dict[str, Dict] = {}
		self.remote_auth: Dict[str, Dict] = {}

		self.sessions: Dict[str, Dict] = {}

	async def set_local_auth(self, uid: str, public_key: str, auth_token: str) -> bool:
		self.local_auth[auth_token] = {
			"local_uid":uid,
			"local_pik":public_key
		}

		print(f"[CONTEXT-MANAGER] Setting local auth: {uid} | {public_key} | {auth_token}")

		return True

	async def set_remote_auth(self, uid: str, public_key: str, auth_token: str) -> bool:
		self.remote_auth[auth_token] = {
			"remote_uid":uid,
			"remote_pik":public_key
		}

		return True