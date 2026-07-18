from typing import Any, Dict

from .base import Certificate

from ..identity.entity import EntityIdentity
from ..domain import DomainIdentity

from ..standards.certificates.types import CertificateType


class DomainManagementCertificate(Certificate):
    """
    Certificate of Domain Administration (CAD).

    Autoriza a un Gestor para administrar
    un dominio específico.
    """

    CERTIFICATE_TYPE = CertificateType.DOMAIN_MANAGEMENT


    def __init__(
        self,
        uid: str,
        issuer: EntityIdentity,
        subject: EntityIdentity,
        domain: DomainIdentity,
        created_at: int,
        expires_at: int | None = None,
        payload: bytes | None = None,
        signature: bytes | None = None,
    ):

        super().__init__(
            uid=uid,
            certificate_type=self.CERTIFICATE_TYPE,
            issuer=issuer,
            subject=subject,
            created_at=created_at,
            expires_at=expires_at,
            payload=payload,
            signature=signature,
        )

        self._domain = domain


    # ======================================================
    # Properties
    # ======================================================

    @property
    def domain(self) -> DomainIdentity:
        return self._domain


    # ======================================================
    # Factory
    # ======================================================

    @classmethod
    def create(
        cls,
        issuer: EntityIdentity,
        subject: EntityIdentity,
        domain: DomainIdentity,
    ) -> "DomainManagementCertificate":

        certificate = cls(
            uid=str(__import__("uuid6").uuid7()),

            issuer=issuer,

            subject=subject,

            domain=domain,

            created_at=__import__("time").time_ns() // 1_000_000_000,

            expires_at=None,
        )


        certificate.sign()

        return certificate


    # ======================================================
    # Payload
    # ======================================================

    def _build_payload(self) -> bytes:

        data = {

            "uid": self.uid,

            "certificate_type":
                self.certificate_type.value,

            "issuer":
                self.issuer.uid,

            "subject":
                self.subject.uid,

            "domain":
                self.domain.uid,

            "created_at":
                self.created_at,

            "expires_at":
                self.expires_at,
        }


        import json


        return json.dumps(
            data,
            separators=(",", ":"),
            sort_keys=True
        ).encode("utf-8")



    # ======================================================
    # Serialization
    # ======================================================

    def to_dict(self):

        data = super().to_dict()

        data["domain"] = self.domain.to_dict(
            include_private=False
        )

        return data



    @classmethod
    def from_dict(
        cls,
        data: Dict[str, Any]
    ):

        certificate = cls(

            uid=data["uid"],

            issuer=EntityIdentity.from_dict(
                data["issuer"]
            ),

            subject=EntityIdentity.from_dict(
                data["subject"]
            ),

            domain=DomainIdentity.from_dict(
                data["domain"]
            ),

            created_at=data["created_at"],

            expires_at=data["expires_at"],

            payload=(
                __import__("base64").b64decode(
                    data["payload"]
                )
                if data["payload"]
                else None
            ),

            signature=(
                __import__("base64").b64decode(
                    data["signature"]
                )
                if data["signature"]
                else None
            ),
        )


        return certificate