from dataclasses import dataclass

from ..identity.identification import (
    EntityIdentity,
    Identification
)

from ..cryptography.identity import (
    CryptographicIdentity
)


@dataclass(frozen=True)
class Domain:
    identity: EntityIdentity
    description: str | None = None

    @property
    def uid(self) -> str:
        return self.identity.identification.uid

    @property
    def name(self) -> str:
        return self.identity.name

    @property
    def cryptographic_identity(self):
        return self.identity.cryptographic_identity

    @staticmethod
    def generate(
        name: str,
        description: str | None = None
    ) -> "Domain":

        return Domain(
            identity=EntityIdentity.generate(
                name=name
            ),
            description=description
        )

    @staticmethod
    def from_database(
        uid: str,
        name: str,
        pik: str,
        description: str | None = None
    ) -> "Domain":
        """
        Reconstruct domain from database data.
        """

        return Domain(
            identity=EntityIdentity(
                identification=Identification(
                    uid=uid
                ),

                cryptographic_identity=CryptographicIdentity(
                    public_key=pik
                ),

                name=name
            ),

            description=description
        )
    
    def export_public(self) -> dict:
        return {
            "identity": self.identity.export_public(),
            "description": self.description
        }

    def to_dict(self) -> dict:
        return {
            "identity": self.identity.to_dict(),
            "description": self.description
        }