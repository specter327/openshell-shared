from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, ClassVar
from uuid import UUID

import hashlib
import json
import secrets
import string

from uuid6 import uuid7

from .types import (
    PASSPORT_TYPE,
    PASSPORT_STATUS
)


@dataclass(slots=True)
class Passport:
    """
    Portable domain-integration passport.

    A passport authorizes an entity to request membership
    in a specific domain through a defined integration
    protocol.

    OPEN:
        The passport is not restricted to a predefined
        entity identity.

        entity_uid = None
        entity_pik = None

    CLOSED:
        The passport is restricted to a specific logical
        and cryptographic identity.

        entity_uid != None
        entity_pik != None
    """

    uid: str

    domain_uid: str

    fingerprint: str

    entity_uid: Optional[str]
    entity_pik: Optional[str]

    security_code: str

    protocol: str
    predefined_role: str
    status: str

    # =====================================================
    # Constants
    # =====================================================

    DEFAULT_SECURITY_CODE_LENGTH: ClassVar[int] = 6

    SECURITY_CODE_ALPHABET: ClassVar[str] = (
        string.ascii_uppercase
        + string.digits
    )

    # =====================================================
    # Representation
    # =====================================================

    def __repr__(self) -> str:

        entity_pik_display = (
            "<UNDEFINED>"
            if self.entity_pik is None
            else "<HIDDEN>"
        )

        return f"""Passport(
    uid={self.uid},
    domain_uid={self.domain_uid},
    fingerprint={self.fingerprint},
    entity_uid={self.entity_uid},
    entity_pik={entity_pik_display},
    security_code=<HIDDEN>,
    protocol={self.protocol},
    predefined_role={self.predefined_role},
    status={self.status}
)"""

    # =====================================================
    # Compatibility properties
    # =====================================================

    @property
    def passport_uid(self) -> str:
        """
        Compatibility alias for repositories using
        PASSPORT_UID.
        """

        return self.uid

    @property
    def passport_fingerprint(self) -> str:
        """
        Compatibility alias for repositories using
        PASSPORT_FINGERPRINT.
        """

        return self.fingerprint

    # =====================================================
    # Normalization
    # =====================================================

    @classmethod
    def _normalize_protocol(
        cls,
        protocol: str
    ) -> str:

        if not isinstance(protocol, str):
            raise TypeError(
                "protocol must be a string"
            )

        normalized = protocol.strip().upper()

        supported_protocols = {
            PASSPORT_TYPE.OPEN.value,
            PASSPORT_TYPE.CLOSED.value,
        }

        if normalized not in supported_protocols:
            raise ValueError(
                f"Unsupported passport protocol: {protocol}"
            )

        return normalized

    @classmethod
    def _normalize_status(
        cls,
        status: str
    ) -> str:

        if not isinstance(status, str):
            raise TypeError(
                "status must be a string"
            )

        normalized = status.strip().upper()

        supported_statuses = {
            PASSPORT_STATUS.ACTIVE.value,
            PASSPORT_STATUS.CONSUMED.value,
            PASSPORT_STATUS.REVOKED.value,
            PASSPORT_STATUS.EXPIRED.value,
            PASSPORT_STATUS.SUSPENDED.value,
        }

        if normalized not in supported_statuses:
            raise ValueError(
                f"Unsupported passport status: {status}"
            )

        return normalized

    @staticmethod
    def _normalize_uuid(
        value: str | UUID,
        field_name: str
    ) -> str:

        try:

            return str(
                UUID(str(value))
            )

        except (
            TypeError,
            ValueError,
            AttributeError
        ) as error:

            raise ValueError(
                f"{field_name} must be a valid UUID"
            ) from error

    @classmethod
    def _normalize_entity_uid(
        cls,
        entity_uid: Optional[str | UUID]
    ) -> Optional[str]:

        if entity_uid is None:
            return None

        return cls._normalize_uuid(
            value=entity_uid,
            field_name="entity_uid"
        )

    @staticmethod
    def _normalize_entity_pik(
        entity_pik: Optional[str]
    ) -> Optional[str]:
        """
        Normalizes the serialized Ed25519 public identity
        key.

        This model treats the PIK as an opaque serialized
        string. Cryptographic decoding and validation belong
        to EntityIdentity or the identity primitives.
        """

        if entity_pik is None:
            return None

        if not isinstance(entity_pik, str):
            raise TypeError(
                "entity_pik must be a string"
            )

        normalized = entity_pik.strip()

        if not normalized:
            raise ValueError(
                "entity_pik cannot be empty"
            )

        return normalized

    @staticmethod
    def _normalize_role(
        predefined_role: str
    ) -> str:

        if not isinstance(predefined_role, str):
            raise TypeError(
                "predefined_role must be a string"
            )

        normalized = (
            predefined_role
            .strip()
            .upper()
        )

        if not normalized:
            raise ValueError(
                "predefined_role cannot be empty"
            )

        return normalized

    @staticmethod
    def _normalize_security_code(
        security_code: str
    ) -> str:

        if not isinstance(security_code, str):
            raise TypeError(
                "security_code must be a string"
            )

        normalized = (
            security_code
            .strip()
            .upper()
        )

        if not normalized:
            raise ValueError(
                "security_code cannot be empty"
            )

        return normalized

    # =====================================================
    # Protocol identity constraints
    # =====================================================

    @classmethod
    def _validate_protocol_identity(
        cls,
        protocol: str,
        entity_uid: Optional[str],
        entity_pik: Optional[str]
    ) -> bool:
        """
        Enforces identity requirements for OPEN and CLOSED
        passports.
        """

        if protocol == PASSPORT_TYPE.OPEN.value:

            if entity_uid is not None:
                raise ValueError(
                    "OPEN passports cannot define entity_uid"
                )

            if entity_pik is not None:
                raise ValueError(
                    "OPEN passports cannot define entity_pik"
                )

            return True

        if protocol == PASSPORT_TYPE.CLOSED.value:

            if entity_uid is None:
                raise ValueError(
                    "CLOSED passports require entity_uid"
                )

            if entity_pik is None:
                raise ValueError(
                    "CLOSED passports require entity_pik"
                )

            return True

        raise ValueError(
            f"Unsupported passport protocol: {protocol}"
        )

    # =====================================================
    # Security code
    # =====================================================

    @classmethod
    def generate_security_code(
        cls,
        length: int = DEFAULT_SECURITY_CODE_LENGTH
    ) -> str:

        if not isinstance(length, int):
            raise TypeError(
                "Security code length must be an integer"
            )

        if length < 4:
            raise ValueError(
                "Security code length must be at least 4"
            )

        return "".join(
            secrets.choice(
                cls.SECURITY_CODE_ALPHABET
            )
            for _ in range(length)
        )

    def verify_security_code(
        self,
        security_code: str
    ) -> bool:
        """
        Compares a presented security code with the
        passport security code using constant-time
        comparison.
        """

        try:

            normalized = (
                self._normalize_security_code(
                    security_code
                )
            )

        except (
            TypeError,
            ValueError
        ):

            return False

        return secrets.compare_digest(
            self.security_code,
            normalized
        )

    # =====================================================
    # Fingerprint
    # =====================================================

    def _fingerprint_payload(self) -> dict:
        """
        Returns the canonical information protected by the
        passport fingerprint.

        The fingerprint itself is excluded to avoid a
        recursive definition.
        """

        return {
            "uid": self.uid,
            "domain_uid": self.domain_uid,
            "entity_uid": self.entity_uid,
            "entity_pik": self.entity_pik,
            "security_code": self.security_code,
            "protocol": self.protocol,
            "predefined_role": self.predefined_role,
            "status": self.status,
        }

    def calculate_fingerprint(self) -> str:

        canonical_data = json.dumps(
            self._fingerprint_payload(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

        return hashlib.sha256(
            canonical_data
        ).hexdigest()

    def verify_fingerprint(self) -> bool:
        """
        Verifies that the passport data matches its
        registered fingerprint.
        """

        if not isinstance(self.fingerprint, str):
            return False

        if not self.fingerprint:
            return False

        expected = self.calculate_fingerprint()

        return secrets.compare_digest(
            self.fingerprint,
            expected
        )

    def refresh_fingerprint(self) -> str:
        """
        Recalculates the fingerprint after an intentional
        passport mutation.
        """

        self.fingerprint = (
            self.calculate_fingerprint()
        )

        return self.fingerprint

    # =====================================================
    # Validation
    # =====================================================

    def validate(self) -> bool:

        # -------------------------------------------------
        # Normalize identifiers
        # -------------------------------------------------

        self.uid = self._normalize_uuid(
            value=self.uid,
            field_name="uid"
        )

        self.domain_uid = self._normalize_uuid(
            value=self.domain_uid,
            field_name="domain_uid"
        )

        self.entity_uid = (
            self._normalize_entity_uid(
                self.entity_uid
            )
        )

        self.entity_pik = (
            self._normalize_entity_pik(
                self.entity_pik
            )
        )

        # -------------------------------------------------
        # Normalize semantic fields
        # -------------------------------------------------

        self.protocol = (
            self._normalize_protocol(
                self.protocol
            )
        )

        self.predefined_role = (
            self._normalize_role(
                self.predefined_role
            )
        )

        self.status = (
            self._normalize_status(
                self.status
            )
        )

        self.security_code = (
            self._normalize_security_code(
                self.security_code
            )
        )

        # -------------------------------------------------
        # Validate OPEN/CLOSED identity requirements
        # -------------------------------------------------

        self._validate_protocol_identity(
            protocol=self.protocol,
            entity_uid=self.entity_uid,
            entity_pik=self.entity_pik
        )

        # -------------------------------------------------
        # Validate fingerprint
        # -------------------------------------------------

        if not isinstance(self.fingerprint, str):
            raise TypeError(
                "fingerprint must be a string"
            )

        if not self.fingerprint:
            raise ValueError(
                "fingerprint cannot be empty"
            )

        if not self.verify_fingerprint():
            raise ValueError(
                "Invalid passport fingerprint"
            )

        return True

    # =====================================================
    # State
    # =====================================================

    @property
    def is_active(self) -> bool:

        return (
            self.status
            == PASSPORT_STATUS.ACTIVE.value
        )

    @property
    def is_open(self) -> bool:

        return (
            self.protocol
            == PASSPORT_TYPE.OPEN.value
        )

    @property
    def is_closed(self) -> bool:

        return (
            self.protocol
            == PASSPORT_TYPE.CLOSED.value
        )

    def set_status(
        self,
        status: str
    ) -> bool:
        """
        Changes the passport status and refreshes its
        fingerprint.

        Persistence remains the repository's responsibility.
        """

        self.status = (
            self._normalize_status(
                status
            )
        )

        self.refresh_fingerprint()

        return True

    # =====================================================
    # Expected entity
    # =====================================================

    def matches_entity(
        self,
        entity_uid: str | UUID,
        entity_pik: str
    ) -> bool:
        """
        Determines whether an authenticated entity matches
        the expected identity of this passport.

        OPEN passports accept any authenticated identity.

        CLOSED passports require both UID and PIK to match.
        """

        if self.is_open:
            return True

        if not self.is_closed:
            return False

        try:

            normalized_uid = (
                self._normalize_uuid(
                    value=entity_uid,
                    field_name="entity_uid"
                )
            )

            normalized_pik = (
                self._normalize_entity_pik(
                    entity_pik
                )
            )

        except (
            TypeError,
            ValueError
        ):

            return False

        if normalized_pik is None:
            return False

        uid_matches = secrets.compare_digest(
            self.entity_uid or "",
            normalized_uid
        )

        pik_matches = secrets.compare_digest(
            self.entity_pik or "",
            normalized_pik
        )

        return (
            uid_matches
            and pik_matches
        )

    # =====================================================
    # Portable integration code
    # =====================================================

    def to_integration_code(self) -> str:
        """
        Returns:

            PassportUID.DomainUID.EntityUID|#.SECURITY_CODE

        ENTITY_PIK is intentionally not included. The
        cryptographic identity must be obtained from the
        authenticated session and compared against the
        stored passport.
        """

        entity_segment = (
            self.entity_uid
            if self.entity_uid is not None
            else "#"
        )

        return (
            f"{self.uid}."
            f"{self.domain_uid}."
            f"{entity_segment}."
            f"{self.security_code}"
        )

    @classmethod
    def parse_integration_code(
        cls,
        integration_code: str
    ) -> dict:
        """
        Parses a portable integration code.

        This does not reconstruct the complete Passport.
        Protocol, role, status, expected PIK and fingerprint
        must be resolved from persistent storage.
        """

        if not isinstance(integration_code, str):
            raise TypeError(
                "integration_code must be a string"
            )

        segments = (
            integration_code
            .strip()
            .split(".")
        )

        if len(segments) != 4:
            raise ValueError(
                "Invalid integration code format"
            )

        (
            passport_uid,
            domain_uid,
            entity_segment,
            security_code,
        ) = segments

        normalized_passport_uid = (
            cls._normalize_uuid(
                value=passport_uid,
                field_name="passport_uid"
            )
        )

        normalized_domain_uid = (
            cls._normalize_uuid(
                value=domain_uid,
                field_name="domain_uid"
            )
        )

        entity_uid = (
            None
            if entity_segment == "#"
            else cls._normalize_uuid(
                value=entity_segment,
                field_name="entity_uid"
            )
        )

        normalized_security_code = (
            cls._normalize_security_code(
                security_code
            )
        )

        return {
            "passport_uid": normalized_passport_uid,
            "domain_uid": normalized_domain_uid,
            "entity_uid": entity_uid,
            "security_code": normalized_security_code,
        }

    # =====================================================
    # Serialization
    # =====================================================

    def to_dict(self) -> dict:

        return {
            "uid": self.uid,
            "domain_uid": self.domain_uid,
            "fingerprint": self.fingerprint,
            "entity_uid": self.entity_uid,
            "entity_pik": self.entity_pik,
            "security_code": self.security_code,
            "protocol": self.protocol,
            "predefined_role": self.predefined_role,
            "status": self.status,
        }

    def to_json(self) -> str:

        return json.dumps(
            self.to_dict(),
            indent=4,
            ensure_ascii=False,
        )

    # =====================================================
    # Deserialization
    # =====================================================

    @classmethod
    def from_dict(
        cls,
        data: dict
    ) -> Passport:

        if not isinstance(data, dict):
            raise TypeError(
                "Passport data must be a dictionary"
            )

        passport = cls(
            uid=data.get("uid"),
            domain_uid=data.get("domain_uid"),
            fingerprint=data.get("fingerprint"),
            entity_uid=data.get("entity_uid"),
            entity_pik=data.get("entity_pik"),
            security_code=data.get(
                "security_code"
            ),
            protocol=data.get("protocol"),
            predefined_role=data.get(
                "predefined_role"
            ),
            status=data.get("status"),
        )

        passport.validate()

        return passport

    @classmethod
    def from_json(
        cls,
        data: str
    ) -> Passport:

        if not isinstance(data, str):
            raise TypeError(
                "Passport JSON data must be a string"
            )

        try:

            decoded = json.loads(data)

        except json.JSONDecodeError as error:

            raise ValueError(
                "Invalid Passport JSON"
            ) from error

        return cls.from_dict(
            decoded
        )

    # =====================================================
    # Creation
    # =====================================================

    @classmethod
    def create(
        cls,
        domain_uid: str | UUID,
        protocol: str,
        predefined_role: str,
        entity_uid: Optional[str | UUID] = None,
        entity_pik: Optional[str] = None,
        security_code: Optional[str] = None,
        security_code_length: int = (
            DEFAULT_SECURITY_CODE_LENGTH
        ),
        status: str = PASSPORT_STATUS.ACTIVE.value,
    ) -> Passport:

        normalized_domain_uid = (
            cls._normalize_uuid(
                value=domain_uid,
                field_name="domain_uid"
            )
        )

        normalized_entity_uid = (
            cls._normalize_entity_uid(
                entity_uid
            )
        )

        normalized_entity_pik = (
            cls._normalize_entity_pik(
                entity_pik
            )
        )

        normalized_protocol = (
            cls._normalize_protocol(
                protocol
            )
        )

        normalized_role = (
            cls._normalize_role(
                predefined_role
            )
        )

        normalized_status = (
            cls._normalize_status(
                status
            )
        )

        cls._validate_protocol_identity(
            protocol=normalized_protocol,
            entity_uid=normalized_entity_uid,
            entity_pik=normalized_entity_pik
        )

        if security_code is None:

            normalized_security_code = (
                cls.generate_security_code(
                    security_code_length
                )
            )

        else:

            normalized_security_code = (
                cls._normalize_security_code(
                    security_code
                )
            )

        passport = cls(
            uid=str(uuid7()),
            domain_uid=normalized_domain_uid,
            fingerprint="",
            entity_uid=normalized_entity_uid,
            entity_pik=normalized_entity_pik,
            security_code=normalized_security_code,
            protocol=normalized_protocol,
            predefined_role=normalized_role,
            status=normalized_status,
        )

        passport.refresh_fingerprint()

        return passport