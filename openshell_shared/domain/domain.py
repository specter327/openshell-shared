from dataclasses import dataclass

from ..identity.entity import EntityIdentity


@dataclass(frozen=True)
class Domain:
    """
    Representa un dominio de OpenShell.

    El dominio posee una identidad criptográfica propia
    (EntityIdentity) y un nombre legible.
    """

    identity: EntityIdentity
    name: str
    description: str | None = None

    @property
    def uid(self) -> str:
        return self.identity.uid

    @property
    def pik(self) -> bytes:
        return self.identity.pik

    @property
    def ppik(self) -> bytes | None:
        return self.identity.ppik

    @property
    def is_local(self) -> bool:
        return self.identity.is_local

    @property
    def is_remote(self) -> bool:
        return self.identity.is_remote

    @classmethod
    def generate(
        cls,
        name: str,
        description: str | None = None
    ) -> "Domain":

        return cls(
            identity=EntityIdentity.create(),
            name=name,
            description=description
        )

    @classmethod
    def from_database(
        cls,
        uid: str,
        name: str,
        pik: str | bytes,
        description: str | None = None
    ) -> "Domain":
        """
        Reconstruye un dominio utilizando únicamente
        la identidad pública almacenada en la base de datos.
        """

        if isinstance(pik, str):
            import base64
            pik = base64.b64decode(pik)

        return cls(
            identity=EntityIdentity(
                uid=uid,
                pik=pik
            ),
            name=name,
            description=description
        )

    def export_public(self) -> dict:
        return {
            "identity": self.identity.to_dict(
                include_private=False
            ),
            "name": self.name,
            "description": self.description
        }

    def to_dict(
        self,
        include_private: bool = False
    ) -> dict:
        return {
            "identity": self.identity.to_dict(
                include_private=include_private
            ),
            "name": self.name,
            "description": self.description
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Domain":
        return cls(
            identity=EntityIdentity.from_dict(
                data["identity"]
            ),
            name=data["name"],
            description=data.get("description")
        )

    def __repr__(self):
        return (
            "Domain(\n"
            f"    name='{self.name}',\n"
            f"    uid='{self.uid}',\n"
            f"    pik_fingerprint={self.identity.pik_fingerprint},\n"
            f"    local={self.is_local}\n"
            ")"
        )