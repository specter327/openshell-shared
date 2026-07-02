# shared/cryptography/certificate.py

# =========================================================
# LIBRARY IMPORTS
# =========================================================

from __future__ import annotations

import json

from dataclasses import dataclass, field
from uuid6 import uuid7
from time import time
from typing import Optional

# =========================================================
# LOCAL IMPORTS
# =========================================================

from .signatures import (
    sign_data,
    verify_signature
)

# =========================================================
# CONSTANTS
# =========================================================

SCHEMA_VERSION: int = 1

STATUS_ACTIVE: str = "ACTIVE"
STATUS_REVOKED: str = "REVOKED"
STATUS_EXPIRED: str = "EXPIRED"
STATUS_COMPROMISED: str = "COMPROMISED"

VALID_STATUSES = {
    STATUS_ACTIVE,
    STATUS_REVOKED,
    STATUS_EXPIRED,
    STATUS_COMPROMISED
}

# =========================================================
# EXCEPTIONS
# =========================================================

class CertificateError(Exception):
    pass


class CertificateValidationError(CertificateError):
    pass


class CertificateSignatureError(CertificateError):
    pass


# =========================================================
# CERTIFICATE
# =========================================================

@dataclass
class Certificate:

    # -----------------------------------------------------
    # SCHEMA
    # -----------------------------------------------------

    schema: int = SCHEMA_VERSION

    # -----------------------------------------------------
    # IDENTITY
    # -----------------------------------------------------

    uid: str = field(default_factory=lambda: str(uuid7()))

    certificate_type: str = ""

    # -----------------------------------------------------
    # ISSUER
    # -----------------------------------------------------

    issuer_uid: str = ""
    issuer_public_key: str = ""

    # -----------------------------------------------------
    # SUBJECT
    # -----------------------------------------------------

    subject_uid: str = ""

    # -----------------------------------------------------
    # CONTENT
    # -----------------------------------------------------

    payload: dict = field(default_factory=dict)

    # -----------------------------------------------------
    # TEMPORAL
    # -----------------------------------------------------

    issued_at: int = field(default_factory=lambda: int(time()))
    expires_at: int = 0

    # -----------------------------------------------------
    # STATUS
    # -----------------------------------------------------

    status: str = STATUS_ACTIVE

    revoked_at: Optional[int] = None

    # -----------------------------------------------------
    # CRYPTOGRAPHIC
    # -----------------------------------------------------

    signature: Optional[str] = None

    # =====================================================
    # FACTORY
    # =====================================================

    @staticmethod
    def generate(
        certificate_type: str,
        issuer_uid: str,
        issuer_public_key: str,
        subject_uid: str,
        payload: dict,
        expires_at: int
    ) -> "Certificate":

        cert = Certificate(
            certificate_type=certificate_type,

            issuer_uid=issuer_uid,
            issuer_public_key=issuer_public_key,

            subject_uid=subject_uid,

            payload=payload,

            expires_at=expires_at
        )

        cert.validate()

        return cert

    # =====================================================
    # VALIDATION
    # =====================================================

    def validate(self):

        if not isinstance(self.schema, int):
            raise CertificateValidationError(
                "schema must be integer"
            )

        if self.schema <= 0:
            raise CertificateValidationError(
                "invalid schema version"
            )

        required_strings = [
            ("uid", self.uid),
            ("certificate_type", self.certificate_type),
            ("issuer_uid", self.issuer_uid),
            ("issuer_public_key", self.issuer_public_key),
            ("subject_uid", self.subject_uid)
        ]

        for field_name, value in required_strings:

            if not isinstance(value, str):
                raise CertificateValidationError(
                    f"{field_name} must be string"
                )

            if not value.strip():
                raise CertificateValidationError(
                    f"{field_name} cannot be empty"
                )

        if not isinstance(self.payload, dict):
            raise CertificateValidationError(
                "payload must be dictionary"
            )

        if not isinstance(self.issued_at, int):
            raise CertificateValidationError(
                "issued_at must be integer"
            )

        if not isinstance(self.expires_at, int):
            raise CertificateValidationError(
                "expires_at must be integer"
            )

        if self.expires_at <= self.issued_at:
            raise CertificateValidationError(
                "expires_at must be greater than issued_at"
            )

        if self.status not in VALID_STATUSES:
            raise CertificateValidationError(
                f"invalid status: {self.status}"
            )

    # =====================================================
    # SIGNATURE PAYLOAD
    # =====================================================

    def signature_payload(self) -> dict:
        """
        ONLY immutable signed data.
        """

        return {
            "schema": self.schema,

            "uid": self.uid,
            "certificate_type": self.certificate_type,

            "issuer_uid": self.issuer_uid,
            "issuer_public_key": self.issuer_public_key,

            "subject_uid": self.subject_uid,

            "payload": self.payload,

            "issued_at": self.issued_at,
            "expires_at": self.expires_at
        }

    # =====================================================
    # CANONICAL PAYLOAD
    # =====================================================

    def canonical_payload(self) -> str:
        """
        Stable deterministic representation.
        """

        return json.dumps(
            self.signature_payload(),
            sort_keys=True,
            separators=(",", ":")
        )

    # =====================================================
    # SIGNING
    # =====================================================

    def sign(
        self,
        issuer_private_key: str
    ):

        self.validate()

        self.signature = sign_data(
            issuer_private_key,
            self.canonical_payload()
        )

    # =====================================================
    # VERIFICATION
    # =====================================================

    def verify(self) -> bool:

        self.validate()

        if not self.signature:
            return False

        return verify_signature(
            self.issuer_public_key,
            self.canonical_payload(),
            self.signature
        )

    # =====================================================
    # STATUS
    # =====================================================

    def revoke(self):

        self.status = STATUS_REVOKED
        self.revoked_at = int(time())

    def is_expired(self) -> bool:
        return time() > self.expires_at

    def is_active(self) -> bool:

        if self.status != STATUS_ACTIVE:
            return False

        if self.is_expired():
            return False

        return self.verify()

    # =====================================================
    # SERIALIZATION
    # =====================================================

    def to_dict(self) -> dict:

        return {
            "schema": self.schema,

            "uid": self.uid,
            "certificate_type": self.certificate_type,

            "issuer_uid": self.issuer_uid,
            "issuer_public_key": self.issuer_public_key,

            "subject_uid": self.subject_uid,

            "payload": self.payload,

            "issued_at": self.issued_at,
            "expires_at": self.expires_at,

            "status": self.status,
            "revoked_at": self.revoked_at,

            "signature": self.signature
        }

    def to_json(self) -> str:

        return json.dumps(
            self.to_dict(),
            indent=4,
            sort_keys=True
        )

    # =====================================================
    # DESERIALIZATION
    # =====================================================

    @staticmethod
    def from_dict(data: dict) -> "Certificate":

        cert = Certificate(
            schema=data["schema"],

            uid=data["uid"],
            certificate_type=data["certificate_type"],

            issuer_uid=data["issuer_uid"],
            issuer_public_key=data["issuer_public_key"],

            subject_uid=data["subject_uid"],

            payload=data["payload"],

            issued_at=data["issued_at"],
            expires_at=data["expires_at"],

            status=data.get(
                "status",
                STATUS_ACTIVE
            ),

            revoked_at=data.get(
                "revoked_at"
            ),

            signature=data.get(
                "signature"
            )
        )

        cert.validate()

        return cert

    @staticmethod
    def from_json(data: str) -> "Certificate":

        return Certificate.from_dict(
            json.loads(data)
        )