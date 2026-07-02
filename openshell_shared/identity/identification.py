from dataclasses import dataclass
from uuid import UUID
from uuid6 import uuid7
from ..cryptography.identity import CryptographicIdentity


@dataclass(frozen=True)
class Identification:
    uid: str

    def __post_init__(self):
        UUID(self.uid)

    def to_string(self) -> str:
        return self.uid

    def to_dict(self) -> dict:
        return {
            "uid": self.uid
        }

    @staticmethod
    def generate() -> "Identification":
        return Identification(uid=str(uuid7()))

@dataclass(frozen=True)
class EntityIdentity:
    identification: Identification
    cryptographic_identity: CryptographicIdentity
    name: str

    @staticmethod
    def generate(name) -> "EntityIdentity":
        return EntityIdentity(
            identification=Identification.generate(),
            cryptographic_identity=CryptographicIdentity.generate(),
            name=name
        )

    def export_public(self) -> dict:
        return {
            "identification": (
                self.identification.to_dict()
            ),

            "cryptographic_identity": (
                self.cryptographic_identity.export_public()
            ),

            "name": self.name
        }

    def to_dict(self) -> dict:
        return {
            "identification": (
                self.identification.to_dict()
            ),

            "cryptographic_identity": (
                self.cryptographic_identity.to_dict()
            ),

            "name": self.name
        }