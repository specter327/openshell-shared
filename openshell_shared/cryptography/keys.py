# shared/cryptography/keyformats.py

from __future__ import annotations

import hashlib
from typing import Final

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class Ed25519KeyFormats:
    """
    Ed25519 key format utilities.

    Canonical internal format:

        RAW bytes

    Public key:
        32 bytes

    Private key seed:
        32 bytes

    Formats:

        STORAGE:
            RAW bytes

        PROCESS:
            HEX

        EXPORT:
            PEM / HEX
    """

    PUBLIC: Final[str] = "PUBLIC"
    PRIVATE: Final[str] = "PRIVATE"

    PEM: Final[str] = "PEM"
    HEX: Final[str] = "HEX"
    RAW: Final[str] = "RAW"

    KEY_SIZE: Final[int] = 32


    # =====================================================
    # DETECTION
    # =====================================================

    @staticmethod
    def is_pem(
        data: str | bytes
    ) -> bool:

        if isinstance(data, bytes):

            return (
                b"-----BEGIN PUBLIC KEY-----" in data
                or
                b"-----BEGIN PRIVATE KEY-----" in data
            )

        if isinstance(data, str):

            return (
                "-----BEGIN PUBLIC KEY-----" in data
                or
                "-----BEGIN PRIVATE KEY-----" in data
            )

        return False


    @staticmethod
    def is_hex(
        data: str | bytes
    ) -> bool:

        if isinstance(data, bytes):

            try:
                data = data.decode("ascii")

            except UnicodeDecodeError:
                return False

        if not isinstance(data, str):
            return False

        data = data.strip()

        if len(data) != 64:
            return False

        try:
            bytes.fromhex(data)
            return True

        except ValueError:
            return False


    @staticmethod
    def is_raw(
        data
    ) -> bool:

        return (
            isinstance(data, bytes)
            and
            len(data) == 32
        )


    @classmethod
    def detect_format(
        cls,
        data
    ) -> str | None:

        if cls.is_pem(data):
            return cls.PEM

        if cls.is_hex(data):
            return cls.HEX

        if cls.is_raw(data):
            return cls.RAW

        return None



    # =====================================================
    # TYPE DETECTION
    # =====================================================

    @classmethod
    def detect_key_type(
        cls,
        data
    ) -> str | None:


        if not cls.is_pem(data):
            return None


        if isinstance(data, bytes):

            if b"BEGIN PUBLIC KEY" in data:
                return cls.PUBLIC

            if b"BEGIN PRIVATE KEY" in data:
                return cls.PRIVATE


        if isinstance(data, str):

            if "BEGIN PUBLIC KEY" in data:
                return cls.PUBLIC

            if "BEGIN PRIVATE KEY" in data:
                return cls.PRIVATE


        return None



    # =====================================================
    # NORMALIZATION
    # =====================================================

    @classmethod
    def normalize_public_key(
        cls,
        key
    ) -> bytes:


        fmt = cls.detect_format(key)


        if fmt == cls.RAW:

            return key


        if fmt == cls.HEX:

            if isinstance(key, bytes):
                key = key.decode("ascii")

            raw = bytes.fromhex(key)

            cls._validate_size(raw)

            return raw


        if fmt == cls.PEM:

            if isinstance(key, str):
                key = key.encode()


            public_key = (
                serialization
                .load_pem_public_key(key)
            )


            if not isinstance(
                public_key,
                Ed25519PublicKey
            ):
                raise ValueError(
                    "Invalid Ed25519 public key"
                )


            return public_key.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw
            )


        raise ValueError(
            "Unsupported public key format"
        )



    @classmethod
    def normalize_private_key(
        cls,
        key
    ) -> bytes:


        fmt = cls.detect_format(key)


        if fmt == cls.RAW:

            return key


        if fmt == cls.HEX:

            if isinstance(key, bytes):
                key = key.decode("ascii")

            raw = bytes.fromhex(key)

            cls._validate_size(raw)

            return raw


        if fmt == cls.PEM:

            if isinstance(key, str):
                key = key.encode()


            private_key = (
                serialization
                .load_pem_private_key(
                    key,
                    password=None
                )
            )


            if not isinstance(
                private_key,
                Ed25519PrivateKey
            ):
                raise ValueError(
                    "Invalid Ed25519 private key"
                )


            return private_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption()
            )


        raise ValueError(
            "Unsupported private key format"
        )



    # =====================================================
    # VALIDATION
    # =====================================================

    @classmethod
    def _validate_size(
        cls,
        raw: bytes
    ):

        if len(raw) != cls.KEY_SIZE:

            raise ValueError(
                "Invalid Ed25519 key size"
            )



    @classmethod
    def validate_public_key(
        cls,
        key
    ) -> bool:

        try:

            cls.normalize_public_key(key)

            return True

        except (ValueError, TypeError):

            return False



    @classmethod
    def validate_private_key(
        cls,
        key
    ) -> bool:

        try:

            cls.normalize_private_key(key)

            return True

        except (ValueError, TypeError):

            return False



    # =====================================================
    # DOMAIN CONVERSION
    # =====================================================

    @classmethod
    def to_storage(
        cls,
        key,
        private=False
    ) -> bytes:
        """
        Database / internal storage.

        Returns RAW bytes.
        """

        if private:
            return cls.normalize_private_key(key)

        return cls.normalize_public_key(key)



    @classmethod
    def to_process(
        cls,
        key,
        private=False
    ) -> str:
        """
        Internal processing format.

        Returns HEX.
        """

        raw = cls.to_storage(
            key,
            private
        )

        return raw.hex()



    @classmethod
    def to_export(
        cls,
        key,
        private=False
    ) -> str:
        """
        External interchange.

        Returns PEM.
        """

        raw = cls.to_storage(
            key,
            private
        )


        if private:

            return (
                Ed25519PrivateKey
                .from_private_bytes(raw)
                .private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()
                )
                .decode()
            )


        return (
            Ed25519PublicKey
            .from_public_bytes(raw)
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode()
        )



    # =====================================================
    # FINGERPRINT
    # =====================================================

    @classmethod
    def fingerprint(
        cls,
        key
    ) -> str:
        """
        Stable SHA256 identity fingerprint.
        """

        raw = cls.normalize_public_key(key)

        return hashlib.sha256(
            raw
        ).hexdigest()