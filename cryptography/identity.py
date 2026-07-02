from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    load_pem_public_key,
    load_der_public_key
)
import base64


def normalize_pik(pik: str) -> str:
    """
    Normalize a public key to canonical PEM format.

    Accepts either:
    - Full PEM  (-----BEGIN PUBLIC KEY----- ... -----END PUBLIC KEY-----)
    - Bare Base64 SubjectPublicKeyInfo DER (the middle line of a PEM block)

    Always returns the canonical PEM string so comparisons and
    fingerprints are format-independent.
    """
    pik = pik.strip()

    if pik.startswith("-----BEGIN"):
        key = load_pem_public_key(pik.encode())
    else:
        # Bare Base64 → DER → key object
        der_bytes = base64.b64decode(pik)
        key = load_der_public_key(der_bytes)

    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def fingerprint_public_key(public_key: str) -> str:
    """
    Compute a format-independent SHA-256 fingerprint.

    Normalizes the key to PEM before hashing so PEM input and
    bare-Base64 input of the same key produce the same fingerprint.
    """
    normalized = normalize_pik(public_key)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(normalized.encode())
    return digest.finalize().hex()


@dataclass(frozen=True)
class PublicIdentity:
    public_key: bytes


@dataclass(frozen=True)
class PrivateIdentity:
    private_key: Ed25519PrivateKey
    public_identity: PublicIdentity

    @staticmethod
    def generate() -> "PrivateIdentity":
        private_key = Ed25519PrivateKey.generate()

        public_key = private_key.public_key()

        return PrivateIdentity(
            private_key=private_key,
            public_identity=PublicIdentity(
                public_key=public_key.public_bytes_raw()
            )
        )

@dataclass(frozen=True)
class CryptographicIdentity:
    public_key: str
    private_key: str | None = None
    algorithm: str = "ed25519"

    @staticmethod
    def generate() -> "CryptographicIdentity":
        # Generate private key
        private_key = Ed25519PrivateKey.generate()

        # Generate public key
        public_key = private_key.public_key()

        # Serialize private key
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Serialize public key
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return CryptographicIdentity(
            public_key=public_bytes.decode(),
            private_key=private_bytes.decode()
        )

    def to_dict(self) -> dict:
        return {
            "public_key":self.public_key,
            "private_key":self.private_key,
            "algorithm":self.algorithm
        }

    def fingerprint(self) -> str:
        return fingerprint_public_key(self.public_key)

    def export_public(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "public_key": self.public_key,
            "fingerprint": self.fingerprint()
        }