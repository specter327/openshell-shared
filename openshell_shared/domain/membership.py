# Library import
from uuid import UUID
from datetime import datetime

from .permissions import Permission

# Classes
class Membership:
    def __init__(
        self,
        entity_uid: UUID,
        domain_uid: UUID,
    ):
        self.entity_uid = entity_uid
        self.domain_uid = domain_uid

        self.permissions: set[Permission] = set()

        self.created_at = datetime.utcnow()

        self.revoked = False