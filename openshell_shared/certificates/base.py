import json
import time
import base64
import hashlib

from uuid6 import uuid7
from typing import Optional, Dict, Any

from ..identity.entity import EntityIdentity
from ..domain.domain import DomainIdentity
from ..standards.certificates.types import CertificateType


class Certificate:
    """
    Base class for every OpenShell certificate.

    A certificate is an immutable document signed by an issuer that
    authorizes a subject for a specific purpose.

    Validation of revocations, trust chains and effective status is
    intentionally outside this class.
    """

    def __repr__(self):
        return (
            f"Certificate(\n"
            f"    uid='{self.uid}',\n"
            f"    type={self.certificate_type.name},\n"
            f"    issuer='{self.issuer.uid}',\n"
            f"    subject='{self.subject.uid}'\n"
            f")"
        )

    def __init__(
        self,
        uid: str,
        certificate_type: CertificateType,
        issuer: EntityIdentity,
        subject: EntityIdentity,
        created_at: int,
        expires_at: Optional[int],
        payload: Optional[bytes] = None,
        signature: Optional[bytes] = None,
    ):

        self._uid = uid

        self._certificate_type = certificate_type

        self._issuer = issuer
        self._subject = subject

        self._created_at = created_at
        self._expires_at = expires_at

        self._payload = payload
        self._signature = signature

    # ==========================================================
    # Properties
    # ==========================================================

    @property
    def uid(self) -> str:
        return self._uid

    @property
    def certificate_type(self) -> CertificateType:
        return self._certificate_type

    @property
    def issuer(self) -> EntityIdentity:
        return self._issuer

    @property
    def subject(self) -> EntityIdentity:
        return self._subject

    @property
    def created_at(self) -> int:
        return self._created_at

    @property
    def expires_at(self) -> Optional[int]:
        return self._expires_at

    @property
    def payload(self) -> Optional[bytes]:
        return self._payload

    @property
    def signature(self) -> Optional[bytes]:
        return self._signature

    @property
    def fingerprint(self) -> str:
        if self._signature is None:
            return ""

        return hashlib.sha256(
            self._signature
        ).hexdigest()

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False

        return time.time() > self.expires_at

    # ==========================================================
    # Payload
    # ==========================================================

    def _build_payload(self) -> bytes:
        """
        Builds the canonical payload signed by the issuer.

        Derived classes should extend this payload with additional
        certificate-specific fields.
        """

        data = {

            "uid": self.uid,

            "certificate_type": self.certificate_type.value,

            "issuer": self.issuer.uid,
            "subject": self.subject.uid,

            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }

        return json.dumps(
            data,
            separators=(",", ":"),
            sort_keys=True
        ).encode("utf-8")

    # ==========================================================
    # Factory
    # ==========================================================

    @classmethod
    def create(
        cls,
        issuer: EntityIdentity,
        subject: EntityIdentity,
        certificate_type: CertificateType,
        expires_at: Optional[int] = None,
    ) -> "Certificate":

        if not issuer.has_private_key:
            raise PermissionError(
                "Issuer must own the private key."
            )

        certificate = cls(
            uid=str(uuid7()),
            certificate_type=certificate_type,
            issuer=issuer,
            subject=subject,
            created_at=int(time.time()),
            expires_at=expires_at,
        )

        certificate.sign()

        return certificate

    # ==========================================================
    # Cryptography
    # ==========================================================

    def sign(self) -> None:

        self._payload = self._build_payload()

        self._signature = self.issuer.sign(
            self._payload
        )

    def verify(self) -> bool:

        if self.payload is None:
            return False

        if self.signature is None:
            return False

        if self.payload != self._build_payload():
            return False

        if self.is_expired:
            return False

        return EntityIdentity.verify_sign(
            data=self.payload,
            pik=self.issuer.pik,
            signature=self.signature,
        )

    # ==========================================================
    # Serialization
    # ==========================================================

    def to_dict(self) -> Dict[str, Any]:

        return {

            "uid": self.uid,

            "certificate_type": self.certificate_type.value,

            "issuer": self.issuer.to_dict(
                include_private=False
            ),

            "subject": self.subject.to_dict(
                include_private=False
            ),

            "created_at": self.created_at,
            "expires_at": self.expires_at,

            "payload": (
                base64.b64encode(
                    self.payload
                ).decode("utf-8")
                if self.payload else None
            ),

            "signature": (
                base64.b64encode(
                    self.signature
                ).decode("utf-8")
                if self.signature else None
            ),
        }

    @classmethod
    def from_dict(
        cls,
        data: Dict[str, Any],
    ) -> "Certificate":

        return cls(

            uid=data["uid"],

            certificate_type=CertificateType(
                data["certificate_type"]
            ),

            issuer=EntityIdentity.from_dict(
                data["issuer"]
            ),

            subject=EntityIdentity.from_dict(
                data["subject"]
            ),

            created_at=data["created_at"],

            expires_at=data["expires_at"],

            payload=(
                base64.b64decode(
                    data["payload"]
                )
                if data["payload"] else None
            ),

            signature=(
                base64.b64decode(
                    data["signature"]
                )
                if data["signature"] else None
            ),
        )

    def to_json(self) -> str:

        return json.dumps(
            self.to_dict(),
            separators=(",", ":")
        )

    @classmethod
    def from_json(
        cls,
        data: str,
    ) -> "Certificate":

        return cls.from_dict(
            json.loads(data)
        )