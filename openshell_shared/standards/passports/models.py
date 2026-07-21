from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional
from uuid import UUID

import hashlib
import json
import secrets
import string

from uuid6 import uuid7

from .types import (
    PASSPORT_STATUS,
    PASSPORT_TYPE,
)


@dataclass(slots=True)
class Passport:
    """
    Portable domain-integration passport.

    A Passport authorizes an authenticated entity to request
    membership in a specific domain through a defined
    integration protocol.

    The Passport records:

    - the CAD that authorized its issuance;
    - the target domain;
    - the predefined role;
    - the expected identity, when applicable;
    - the usage policy;
    - the current number of consumed uses.

    OPEN
    ----

    The Passport is not restricted to a predefined entity.

        entity_uid = None
        entity_pik = None

    An OPEN Passport may be:

    - limited:
        max_uses >= 1

    - unlimited:
        max_uses = None

    Each successful membership creation consumes one use.

    When a limited OPEN Passport reaches max_uses:

        status = EXHAUSTED

    CLOSED
    ------

    The Passport is restricted to one predefined logical and
    cryptographic identity.

        entity_uid != None
        entity_pik != None

    A CLOSED Passport is always single-use:

        max_uses = 1

    After its only successful use:

        uses = 1
        status = CONSUMED

    Important
    ---------

    This model defines the Passport's intrinsic rules.

    It does not:

    - validate CG certificates;
    - validate CAD certificates;
    - query memberships;
    - access persistent storage;
    - coordinate transactions;
    - perform authorization against the local Manager.

    Those responsibilities belong to the application and
    persistence layers.
    """

    uid: str

    cad_uid: str
    domain_uid: str

    fingerprint: str

    entity_uid: Optional[str]
    entity_pik: Optional[str]

    security_code: str

    protocol: str
    predefined_role: str
    status: str

    max_uses: Optional[int] = 1
    uses: int = 0

    # =====================================================
    # Constants
    # =====================================================

    DEFAULT_SECURITY_CODE_LENGTH: ClassVar[int] = 6

    DEFAULT_OPEN_MAX_USES: ClassVar[int] = 1

    SECURITY_CODE_ALPHABET: ClassVar[str] = (
        string.ascii_uppercase
        + string.digits
    )

    # =====================================================
    # Representation
    # =====================================================

    def __repr__(
        self
    ) -> str:

        entity_pik_display = (
            "<UNDEFINED>"
            if self.entity_pik is None
            else "<HIDDEN>"
        )

        max_uses_display = (
            "UNLIMITED"
            if self.max_uses is None
            else str(self.max_uses)
        )

        remaining_uses_display = (
            "UNLIMITED"
            if self.remaining_uses is None
            else str(self.remaining_uses)
        )

        return f"""Passport(
    uid={self.uid},
    cad_uid={self.cad_uid},
    domain_uid={self.domain_uid},
    fingerprint={self.fingerprint},
    entity_uid={self.entity_uid},
    entity_pik={entity_pik_display},
    security_code=<HIDDEN>,
    protocol={self.protocol},
    predefined_role={self.predefined_role},
    status={self.status},
    max_uses={max_uses_display},
    uses={self.uses},
    remaining_uses={remaining_uses_display}
)"""

    # =====================================================
    # Compatibility properties
    # =====================================================

    @property
    def passport_uid(
        self
    ) -> str:
        """
        Compatibility alias for persistence adapters using
        passport_uid.
        """

        return self.uid

    @property
    def passport_fingerprint(
        self
    ) -> str:
        """
        Compatibility alias for persistence adapters using
        passport_fingerprint.
        """

        return self.fingerprint

    # =====================================================
    # Identifier normalization
    # =====================================================

    @staticmethod
    def _normalize_uuid(
        value: str | UUID,
        field_name: str
    ) -> str:

        try:

            return str(
                UUID(
                    str(value)
                )
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
        Normalize the serialized public identity key.

        The Passport treats the PIK as an opaque serialized
        string.

        Cryptographic decoding and validation belong to the
        identity primitives.
        """

        if entity_pik is None:

            return None

        if not isinstance(
            entity_pik,
            str
        ):

            raise TypeError(
                "entity_pik must be a string"
            )

        normalized = (
            entity_pik
            .strip()
        )

        if not normalized:

            raise ValueError(
                "entity_pik cannot be empty"
            )

        return normalized

    # =====================================================
    # Semantic normalization
    # =====================================================

    @classmethod
    def _normalize_protocol(
        cls,
        protocol: str
    ) -> str:

        if not isinstance(
            protocol,
            str
        ):

            raise TypeError(
                "protocol must be a string"
            )

        normalized = (
            protocol
            .strip()
            .upper()
        )

        supported_protocols = {
            PASSPORT_TYPE.OPEN.value,
            PASSPORT_TYPE.CLOSED.value,
        }

        if normalized not in supported_protocols:

            raise ValueError(
                f"Unsupported passport protocol: "
                f"{protocol}"
            )

        return normalized

    @classmethod
    def _normalize_status(
        cls,
        status: str
    ) -> str:

        if not isinstance(
            status,
            str
        ):

            raise TypeError(
                "status must be a string"
            )

        normalized = (
            status
            .strip()
            .upper()
        )

        supported_statuses = {
            PASSPORT_STATUS.ACTIVE.value,
            PASSPORT_STATUS.INACTIVE.value,
            PASSPORT_STATUS.CONSUMED.value,
            PASSPORT_STATUS.EXHAUSTED.value,
            PASSPORT_STATUS.REVOKED.value,
            PASSPORT_STATUS.EXPIRED.value,
            PASSPORT_STATUS.SUSPENDED.value,
        }

        if normalized not in supported_statuses:

            raise ValueError(
                f"Unsupported passport status: "
                f"{status}"
            )

        return normalized

    @staticmethod
    def _normalize_role(
        predefined_role: str
    ) -> str:

        if not isinstance(
            predefined_role,
            str
        ):

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

        if not isinstance(
            security_code,
            str
        ):

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
    # Usage normalization
    # =====================================================

    @staticmethod
    def _normalize_max_uses(
        max_uses: Optional[int]
    ) -> Optional[int]:
        """
        Normalize the maximum number of allowed uses.

        None means unlimited use.
        """

        if max_uses is None:

            return None

        if isinstance(
            max_uses,
            bool
        ):

            raise TypeError(
                "max_uses must be an integer or None"
            )

        if not isinstance(
            max_uses,
            int
        ):

            raise TypeError(
                "max_uses must be an integer or None"
            )

        if max_uses < 1:

            raise ValueError(
                "max_uses must be at least 1"
            )

        return max_uses

    @staticmethod
    def _normalize_uses(
        uses: int
    ) -> int:

        if isinstance(
            uses,
            bool
        ):

            raise TypeError(
                "uses must be an integer"
            )

        if not isinstance(
            uses,
            int
        ):

            raise TypeError(
                "uses must be an integer"
            )

        if uses < 0:

            raise ValueError(
                "uses cannot be negative"
            )

        return uses

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
        Enforce identity requirements for OPEN and CLOSED
        Passports.
        """

        if protocol == PASSPORT_TYPE.OPEN.value:

            if entity_uid is not None:

                raise ValueError(
                    "OPEN passports cannot define "
                    "entity_uid"
                )

            if entity_pik is not None:

                raise ValueError(
                    "OPEN passports cannot define "
                    "entity_pik"
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
            f"Unsupported passport protocol: "
            f"{protocol}"
        )

    # =====================================================
    # Usage policy constraints
    # =====================================================

    @classmethod
    def _validate_usage_policy(
        cls,
        protocol: str,
        max_uses: Optional[int],
        uses: int,
        status: str
    ) -> bool:
        """
        Validate usage limits, counters and terminal states.

        CLOSED:
            max_uses = 1
            uses in {0, 1}
            uses = 1 requires CONSUMED

        OPEN:
            max_uses may be None
            finite exhaustion requires EXHAUSTED
            CONSUMED is not used
        """

        # -------------------------------------------------
        # CLOSED Passport
        # -------------------------------------------------

        if protocol == PASSPORT_TYPE.CLOSED.value:

            if max_uses != 1:

                raise ValueError(
                    "CLOSED passports must have "
                    "max_uses=1"
                )

            if uses > 1:

                raise ValueError(
                    "CLOSED passports cannot be used "
                    "more than once"
                )

            if (
                uses == 1
                and status
                != PASSPORT_STATUS.CONSUMED.value
            ):

                raise ValueError(
                    "A used CLOSED passport must have "
                    "status CONSUMED"
                )

            if (
                status
                == PASSPORT_STATUS.CONSUMED.value
                and uses != 1
            ):

                raise ValueError(
                    "A CONSUMED CLOSED passport must "
                    "have uses=1"
                )

            if (
                status
                == PASSPORT_STATUS.EXHAUSTED.value
            ):

                raise ValueError(
                    "CLOSED passports cannot use status "
                    "EXHAUSTED"
                )

            return True

        # -------------------------------------------------
        # OPEN Passport
        # -------------------------------------------------

        if protocol == PASSPORT_TYPE.OPEN.value:

            if (
                max_uses is not None
                and uses > max_uses
            ):

                raise ValueError(
                    "uses cannot exceed max_uses"
                )

            if (
                status
                == PASSPORT_STATUS.CONSUMED.value
            ):

                raise ValueError(
                    "OPEN passports must use EXHAUSTED, "
                    "not CONSUMED"
                )

            if max_uses is None:

                if (
                    status
                    == PASSPORT_STATUS.EXHAUSTED.value
                ):

                    raise ValueError(
                        "An unlimited OPEN passport "
                        "cannot be EXHAUSTED"
                    )

                return True

            limit_reached = (
                uses >= max_uses
            )

            if (
                limit_reached
                and status
                != PASSPORT_STATUS.EXHAUSTED.value
            ):

                raise ValueError(
                    "An OPEN passport whose usage limit "
                    "was reached must be EXHAUSTED"
                )

            if (
                status
                == PASSPORT_STATUS.EXHAUSTED.value
                and not limit_reached
            ):

                raise ValueError(
                    "EXHAUSTED requires the OPEN passport "
                    "usage limit to be reached"
                )

            return True

        raise ValueError(
            f"Unsupported passport protocol: "
            f"{protocol}"
        )

    # =====================================================
    # Security code
    # =====================================================

    @classmethod
    def generate_security_code(
        cls,
        length: int = DEFAULT_SECURITY_CODE_LENGTH
    ) -> str:

        if isinstance(
            length,
            bool
        ):

            raise TypeError(
                "Security code length must be an integer"
            )

        if not isinstance(
            length,
            int
        ):

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
        Compare a presented security code against the
        Passport security code using constant-time
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

    def _fingerprint_payload(
        self
    ) -> dict:
        """
        Return the canonical Passport information protected
        by the fingerprint.

        Mutable usage state is included so that changes to:

        - uses;
        - max_uses;
        - status;

        require a new fingerprint.
        """

        return {
            "uid": self.uid,
            "cad_uid": self.cad_uid,
            "domain_uid": self.domain_uid,
            "entity_uid": self.entity_uid,
            "entity_pik": self.entity_pik,
            "security_code": self.security_code,
            "protocol": self.protocol,
            "predefined_role": self.predefined_role,
            "status": self.status,
            "max_uses": self.max_uses,
            "uses": self.uses,
        }

    def calculate_fingerprint(
        self
    ) -> str:

        canonical_data = json.dumps(
            self._fingerprint_payload(),
            sort_keys=True,
            separators=(
                ",",
                ":"
            ),
            ensure_ascii=False,
        ).encode(
            "utf-8"
        )

        return hashlib.sha256(
            canonical_data
        ).hexdigest()

    def verify_fingerprint(
        self
    ) -> bool:
        """
        Verify that the Passport data matches its registered
        fingerprint.
        """

        if not isinstance(
            self.fingerprint,
            str
        ):

            return False

        if not self.fingerprint:

            return False

        expected = (
            self.calculate_fingerprint()
        )

        return secrets.compare_digest(
            self.fingerprint,
            expected
        )

    def refresh_fingerprint(
        self
    ) -> str:
        """
        Recalculate the fingerprint after an intentional
        Passport mutation.
        """

        self.fingerprint = (
            self.calculate_fingerprint()
        )

        return self.fingerprint

    # =====================================================
    # Validation
    # =====================================================

    def validate(
        self
    ) -> bool:

        # -------------------------------------------------
        # Normalize identifiers
        # -------------------------------------------------

        self.uid = self._normalize_uuid(
            value=self.uid,
            field_name="uid"
        )

        self.cad_uid = self._normalize_uuid(
            value=self.cad_uid,
            field_name="cad_uid"
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
        # Normalize usage state
        # -------------------------------------------------

        self.max_uses = (
            self._normalize_max_uses(
                self.max_uses
            )
        )

        self.uses = (
            self._normalize_uses(
                self.uses
            )
        )

        # -------------------------------------------------
        # Validate protocol rules
        # -------------------------------------------------

        self._validate_protocol_identity(
            protocol=self.protocol,
            entity_uid=self.entity_uid,
            entity_pik=self.entity_pik
        )

        self._validate_usage_policy(
            protocol=self.protocol,
            max_uses=self.max_uses,
            uses=self.uses,
            status=self.status
        )

        # -------------------------------------------------
        # Validate fingerprint
        # -------------------------------------------------

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
    # Protocol properties
    # =====================================================

    @property
    def is_open(
        self
    ) -> bool:

        return (
            self.protocol
            == PASSPORT_TYPE.OPEN.value
        )

    @property
    def is_closed(
        self
    ) -> bool:

        return (
            self.protocol
            == PASSPORT_TYPE.CLOSED.value
        )

    # =====================================================
    # State properties
    # =====================================================

    @property
    def is_active(
        self
    ) -> bool:

        return (
            self.status
            == PASSPORT_STATUS.ACTIVE.value
        )

    @property
    def is_inactive(
        self
    ) -> bool:

        return (
            self.status
            == PASSPORT_STATUS.INACTIVE.value
        )

    @property
    def is_suspended(
        self
    ) -> bool:

        return (
            self.status
            == PASSPORT_STATUS.SUSPENDED.value
        )

    @property
    def is_revoked(
        self
    ) -> bool:

        return (
            self.status
            == PASSPORT_STATUS.REVOKED.value
        )

    @property
    def is_expired(
        self
    ) -> bool:

        return (
            self.status
            == PASSPORT_STATUS.EXPIRED.value
        )

    @property
    def is_consumed(
        self
    ) -> bool:

        return (
            self.status
            == PASSPORT_STATUS.CONSUMED.value
        )

    @property
    def is_exhausted(
        self
    ) -> bool:

        if self.is_closed:

            return (
                self.uses >= 1
            )

        if self.max_uses is None:

            return False

        return (
            self.uses >= self.max_uses
        )

    @property
    def is_terminal(
        self
    ) -> bool:
        """
        Return whether the Passport reached a state from
        which normal use cannot resume.
        """

        return self.status in {
            PASSPORT_STATUS.CONSUMED.value,
            PASSPORT_STATUS.EXHAUSTED.value,
            PASSPORT_STATUS.REVOKED.value,
            PASSPORT_STATUS.EXPIRED.value,
        }

    # =====================================================
    # Usage properties
    # =====================================================

    @property
    def is_unlimited(
        self
    ) -> bool:

        return (
            self.is_open
            and self.max_uses is None
        )

    @property
    def remaining_uses(
        self
    ) -> Optional[int]:
        """
        Return the number of remaining uses.

        None means unlimited.
        """

        if self.max_uses is None:

            return None

        return max(
            self.max_uses - self.uses,
            0
        )

    @property
    def can_be_used(
        self
    ) -> bool:
        """
        Evaluate only the Passport's intrinsic availability.

        This does not validate:

        - CG validity;
        - CAD validity;
        - membership existence;
        - authenticated session identity;
        - authorization of the local Manager.
        """

        if not self.is_active:

            return False

        if self.is_closed:

            return (
                self.uses == 0
            )

        if self.max_uses is None:

            return True

        return (
            self.uses < self.max_uses
        )

    # =====================================================
    # State mutation
    # =====================================================

    def set_status(
        self,
        status: str
    ) -> bool:
        """
        Change the Passport status while preserving internal
        consistency.

        Persistence remains the repository's responsibility.
        """

        normalized_status = (
            self._normalize_status(
                status
            )
        )

        previous_status = (
            self.status
        )

        self.status = (
            normalized_status
        )

        try:

            self._validate_usage_policy(
                protocol=self.protocol,
                max_uses=self.max_uses,
                uses=self.uses,
                status=self.status
            )

        except Exception:

            self.status = (
                previous_status
            )

            raise

        self.refresh_fingerprint()

        return True

    def activate(
        self
    ) -> bool:

        if self.is_terminal:

            raise ValueError(
                "A terminal Passport cannot be activated"
            )

        return self.set_status(
            PASSPORT_STATUS.ACTIVE.value
        )

    def deactivate(
        self
    ) -> bool:

        if self.is_terminal:

            raise ValueError(
                "A terminal Passport cannot be deactivated"
            )

        return self.set_status(
            PASSPORT_STATUS.INACTIVE.value
        )

    def suspend(
        self
    ) -> bool:

        if self.is_terminal:

            raise ValueError(
                "A terminal Passport cannot be suspended"
            )

        return self.set_status(
            PASSPORT_STATUS.SUSPENDED.value
        )

    def revoke(
        self
    ) -> bool:

        if self.is_consumed:

            raise ValueError(
                "A consumed CLOSED Passport cannot be "
                "revoked"
            )

        if (
            self.status
            == PASSPORT_STATUS.REVOKED.value
        ):

            return True

        self.status = (
            PASSPORT_STATUS.REVOKED.value
        )

        self.refresh_fingerprint()

        return True

    def expire(
        self
    ) -> bool:

        if self.is_consumed:

            raise ValueError(
                "A consumed CLOSED Passport cannot be "
                "expired"
            )

        if (
            self.status
            == PASSPORT_STATUS.EXPIRED.value
        ):

            return True

        self.status = (
            PASSPORT_STATUS.EXPIRED.value
        )

        self.refresh_fingerprint()

        return True

    # =====================================================
    # Consumption
    # =====================================================

    def consume(
        self
    ) -> int:
        """
        Consume exactly one authorized use.

        CLOSED:
            uses becomes 1;
            status becomes CONSUMED.

        OPEN limited:
            uses increments;
            status becomes EXHAUSTED when max_uses is
            reached.

        OPEN unlimited:
            uses increments;
            status remains ACTIVE.

        This operation mutates only the in-memory domain
        object.

        The application layer must execute membership
        creation and Passport persistence atomically.
        """

        if not self.is_active:

            raise ValueError(
                "Passport is not active"
            )

        if not self.can_be_used:

            raise ValueError(
                "Passport has no remaining uses"
            )

        previous_uses = (
            self.uses
        )

        previous_status = (
            self.status
        )

        self.uses += 1

        try:

            if self.is_closed:

                self.status = (
                    PASSPORT_STATUS.CONSUMED.value
                )

            elif (
                self.max_uses is not None
                and self.uses >= self.max_uses
            ):

                self.status = (
                    PASSPORT_STATUS.EXHAUSTED.value
                )

            self._validate_usage_policy(
                protocol=self.protocol,
                max_uses=self.max_uses,
                uses=self.uses,
                status=self.status
            )

        except Exception:

            self.uses = (
                previous_uses
            )

            self.status = (
                previous_status
            )

            raise

        self.refresh_fingerprint()

        return self.uses

    # =====================================================
    # Expected entity
    # =====================================================

    def matches_entity(
        self,
        entity_uid: str | UUID,
        entity_pik: str
    ) -> bool:
        """
        Determine whether an authenticated entity matches
        the Passport identity policy.

        OPEN Passports accept any authenticated entity.

        CLOSED Passports require both UID and PIK to match.
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

    def to_integration_code(
        self
    ) -> str:
        """
        Return:

            PassportUID.DomainUID.EntityUID|#.SecurityCode

        CAD UID is intentionally omitted because the
        authoritative value must be resolved from persistent
        storage.

        Entity PIK is intentionally omitted because it must
        be obtained from the authenticated session.
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
        Parse a portable integration code.

        The result does not reconstruct a Passport.

        CAD, protocol, role, status, expected PIK, usage
        policy and fingerprint must be resolved from trusted
        persistent storage.
        """

        if not isinstance(
            integration_code,
            str
        ):

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

    def to_dict(
        self
    ) -> dict:

        return {
            "uid": self.uid,
            "cad_uid": self.cad_uid,
            "domain_uid": self.domain_uid,
            "fingerprint": self.fingerprint,
            "entity_uid": self.entity_uid,
            "entity_pik": self.entity_pik,
            "security_code": self.security_code,
            "protocol": self.protocol,
            "predefined_role": self.predefined_role,
            "status": self.status,
            "max_uses": self.max_uses,
            "uses": self.uses,
        }

    def to_json(
        self
    ) -> str:

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

        if not isinstance(
            data,
            dict
        ):

            raise TypeError(
                "Passport data must be a dictionary"
            )

        protocol = (
            data.get(
                "protocol"
            )
        )

        # Compatibility with Passports serialized before
        # usage limits were introduced.
        if "max_uses" in data:

            max_uses = (
                data.get(
                    "max_uses"
                )
            )

        else:

            max_uses = 1

        uses = (
            data.get(
                "uses",
                0
            )
        )

        passport = cls(
            uid=data.get(
                "uid"
            ),
            cad_uid=data.get(
                "cad_uid"
            ),
            domain_uid=data.get(
                "domain_uid"
            ),
            fingerprint=data.get(
                "fingerprint"
            ),
            entity_uid=data.get(
                "entity_uid"
            ),
            entity_pik=data.get(
                "entity_pik"
            ),
            security_code=data.get(
                "security_code"
            ),
            protocol=protocol,
            predefined_role=data.get(
                "predefined_role"
            ),
            status=data.get(
                "status"
            ),
            max_uses=max_uses,
            uses=uses,
        )

        passport.validate()

        return passport

    @classmethod
    def from_json(
        cls,
        data: str
    ) -> Passport:

        if not isinstance(
            data,
            str
        ):

            raise TypeError(
                "Passport JSON data must be a string"
            )

        try:

            decoded = json.loads(
                data
            )

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
        cad_uid: str | UUID,
        domain_uid: str | UUID,
        protocol: str,
        predefined_role: str,
        entity_uid: Optional[str | UUID] = None,
        entity_pik: Optional[str] = None,
        security_code: Optional[str] = None,
        security_code_length: int = (
            DEFAULT_SECURITY_CODE_LENGTH
        ),
        status: str = (
            PASSPORT_STATUS.ACTIVE.value
        ),
        max_uses: Optional[int] = (
            DEFAULT_OPEN_MAX_USES
        ),
    ) -> Passport:
        """
        Create a new Passport.

        OPEN:
            max_uses >= 1:
                limited Passport

            max_uses = None:
                unlimited Passport

        CLOSED:
            max_uses is always normalized to 1.

            Any explicit value other than None or 1 is
            rejected.
        """

        normalized_cad_uid = (
            cls._normalize_uuid(
                value=cad_uid,
                field_name="cad_uid"
            )
        )

        normalized_domain_uid = (
            cls._normalize_uuid(
                value=domain_uid,
                field_name="domain_uid"
            )
        )

        normalized_protocol = (
            cls._normalize_protocol(
                protocol
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

        # -------------------------------------------------
        # Resolve usage policy
        # -------------------------------------------------

        if (
            normalized_protocol
            == PASSPORT_TYPE.CLOSED.value
        ):

            if max_uses not in (
                None,
                1
            ):

                raise ValueError(
                    "CLOSED passports cannot define "
                    "more than one use"
                )

            normalized_max_uses = 1

        else:

            normalized_max_uses = (
                cls._normalize_max_uses(
                    max_uses
                )
            )

        normalized_uses = 0

        cls._validate_usage_policy(
            protocol=normalized_protocol,
            max_uses=normalized_max_uses,
            uses=normalized_uses,
            status=normalized_status
        )

        # -------------------------------------------------
        # Resolve security code
        # -------------------------------------------------

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

        # -------------------------------------------------
        # Construct Passport
        # -------------------------------------------------

        passport = cls(
            uid=str(
                uuid7()
            ),
            cad_uid=normalized_cad_uid,
            domain_uid=normalized_domain_uid,
            fingerprint="",
            entity_uid=normalized_entity_uid,
            entity_pik=normalized_entity_pik,
            security_code=normalized_security_code,
            protocol=normalized_protocol,
            predefined_role=normalized_role,
            status=normalized_status,
            max_uses=normalized_max_uses,
            uses=normalized_uses,
        )

        passport.refresh_fingerprint()

        return passport