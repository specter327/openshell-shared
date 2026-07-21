from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from uuid import UUID

import hashlib
import json
import secrets
import string

from uuid6 import uuid7
from .types import PASSPORT_TYPE, PASSPORT_STATUS


@dataclass(slots=True)
class Passport:
    """
    Portable domain-integration passport.

    The passport authorizes an entity to request membership
    in a specific domain using a defined integration protocol.

    Protocol semantics:

    OPEN:
        The passport is not restricted to a predefined entity.

    CLOSED:
        The passport is restricted to a specific entity UID.
    """

    uid: str
    domain_uid: str
    fingerprint: str

    entity_uid: Optional[str]

    security_code: str
    protocol: str
    predefined_role: str
    status: str

    # =====================================================
    # Constants
    # =====================================================

    DEFAULT_SECURITY_CODE_LENGTH = 6

    SECURITY_CODE_ALPHABET = (
        string.ascii_uppercase
        + string.digits
    )

    # =====================================================
    # Representation
    # =====================================================

    def __repr__(self) -> str:

        return f"""Passport(
    uid={self.uid},
    domain_uid={self.domain_uid},
    fingerprint={self.fingerprint},
    entity_uid={self.entity_uid},
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
        Compatibility alias for repositories that use
        the PASSPORT_UID database column name.
        """

        return self.uid

    @property
    def passport_fingerprint(self) -> str:
        """
        Compatibility alias for repositories that use
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

        if normalized not in {
            PASSPORT_TYPE.OPEN.value,
            PASSPORT_TYPE.CLOSED.value,
        }:
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
            return str(UUID(str(value)))

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
            entity_uid,
            "entity_uid"
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

    # =====================================================
    # Fingerprint
    # =====================================================

    def _fingerprint_payload(self) -> dict:
        """
        Returns the canonical information protected by
        the passport fingerprint.

        The fingerprint itself is deliberately excluded.
        """

        return {
            "uid": self.uid,
            "domain_uid": self.domain_uid,
            "entity_uid": self.entity_uid,
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
        Verifies that the passport fields have not changed
        since its fingerprint was calculated.
        """

        expected = self.calculate_fingerprint()

        return secrets.compare_digest(
            self.fingerprint,
            expected
        )

    def refresh_fingerprint(self) -> str:
        """
        Recalculates the fingerprint after an intentional
        mutation of the passport.
        """

        self.fingerprint = (
            self.calculate_fingerprint()
        )

        return self.fingerprint

    # =====================================================
    # Validation
    # =====================================================

    def validate(self) -> bool:

        self.uid = self._normalize_uuid(
            self.uid,
            "uid"
        )

        self.domain_uid = self._normalize_uuid(
            self.domain_uid,
            "domain_uid"
        )

        self.entity_uid = (
            self._normalize_entity_uid(
                self.entity_uid
            )
        )

        self.protocol = (
            self._normalize_protocol(
                self.protocol
            )
        )

        self.status = (
            self._normalize_status(
                self.status
            )
        )

        if not isinstance(
            self.security_code,
            str
        ):
            raise TypeError(
                "security_code must be a string"
            )

        if not self.security_code.strip():
            raise ValueError(
                "security_code cannot be empty"
            )

        self.security_code = (
            self.security_code.strip().upper()
        )

        if not isinstance(
            self.predefined_role,
            str
        ):
            raise TypeError(
                "predefined_role must be a string"
            )

        if not self.predefined_role.strip():
            raise ValueError(
                "predefined_role cannot be empty"
            )

        self.predefined_role = (
            self.predefined_role.strip().upper()
        )

        if (
            self.protocol
            == self.PROTOCOL_OPEN
            and self.entity_uid is not None
        ):
            raise ValueError(
                "OPEN passports cannot define entity_uid"
            )

        if (
            self.protocol
            == self.PROTOCOL_CLOSED
            and self.entity_uid is None
        ):
            raise ValueError(
                "CLOSED passports require entity_uid"
            )

        if not isinstance(
            self.fingerprint,
            str
        ):
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
        Changes the status and regenerates the fingerprint.

        This mutates the logical passport object. Persisting
        that change remains the repository's responsibility.
        """

        self.status = self._normalize_status(
            status
        )

        self.refresh_fingerprint()

        return True

    # =====================================================
    # Portable integration code
    # =====================================================

    def to_integration_code(self) -> str:
        """
        Returns:

            PassportUID.DomainUID.EntityUID|#.SECURITY_CODE
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
        Parses the portable integration code.

        This does not reconstruct the complete Passport
        because protocol, role, status and fingerprint must
        be resolved from persistent storage.
        """

        if not isinstance(
            integration_code,
            str
        ):
            raise TypeError(
                "integration_code must be a string"
            )

        segments = integration_code.strip().split(
            "."
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
                passport_uid,
                "passport_uid"
            )
        )

        normalized_domain_uid = (
            cls._normalize_uuid(
                domain_uid,
                "domain_uid"
            )
        )

        entity_uid = (
            None
            if entity_segment == "#"
            else cls._normalize_uuid(
                entity_segment,
                "entity_uid"
            )
        )

        if not security_code:
            raise ValueError(
                "Security code cannot be empty"
            )

        return {
            "passport_uid": (
                normalized_passport_uid
            ),
            "domain_uid": (
                normalized_domain_uid
            ),
            "entity_uid": entity_uid,
            "security_code": (
                security_code.upper()
            ),
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
            "security_code": self.security_code,
            "protocol": self.protocol,
            "predefined_role": (
                self.predefined_role
            ),
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
        entity_uid: Optional[
            str | UUID
        ] = None,
        security_code: Optional[str] = None,
        security_code_length: int = (
            DEFAULT_SECURITY_CODE_LENGTH
        ),
        status: str = PASSPORT_STATUS.ACTIVE.value,
    ) -> Passport:

        normalized_domain_uid = (
            cls._normalize_uuid(
                domain_uid,
                "domain_uid"
            )
        )

        normalized_entity_uid = (
            cls._normalize_entity_uid(
                entity_uid
            )
        )

        normalized_protocol = (
            cls._normalize_protocol(
                protocol
            )
        )

        normalized_status = (
            cls._normalize_status(
                status
            )
        )

        if (
            normalized_protocol
            == PASSPORT_TYPE.OPEN.value
            and normalized_entity_uid is not None
        ):
            raise ValueError(
                "OPEN passports cannot define entity_uid"
            )

        if (
            normalized_protocol
            == PASSPORT_TYPE.CLOSED.value
            and normalized_entity_uid is None
        ):
            raise ValueError(
                "CLOSED passports require entity_uid"
            )

        if not isinstance(
            predefined_role,
            str
        ):
            raise TypeError(
                "predefined_role must be a string"
            )

        normalized_role = (
            predefined_role.strip().upper()
        )

        if not normalized_role:
            raise ValueError(
                "predefined_role cannot be empty"
            )

        if security_code is None:

            normalized_security_code = (
                cls.generate_security_code(
                    security_code_length
                )
            )

        else:

            if not isinstance(
                security_code,
                str
            ):
                raise TypeError(
                    "security_code must be a string"
                )

            normalized_security_code = (
                security_code.strip().upper()
            )

            if not normalized_security_code:
                raise ValueError(
                    "security_code cannot be empty"
                )

        passport = cls(
            uid=str(uuid7()),
            domain_uid=normalized_domain_uid,
            fingerprint="",
            entity_uid=normalized_entity_uid,
            security_code=(
                normalized_security_code
            ),
            protocol=normalized_protocol,
            predefined_role=normalized_role,
            status=normalized_status,
        )

        passport.refresh_fingerprint()

        return passport