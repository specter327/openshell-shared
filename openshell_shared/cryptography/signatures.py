# Library import
import json
import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey
)

from cryptography.hazmat.primitives import serialization


# Functions
def canonicalize(data: dict) -> bytes:
    """
    Convert dictionary to canonical JSON bytes
    """

    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":")
    ).encode()


def sign_data(
    private_key_pem: str,
    data: dict
) -> str:

    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None
    )

    payload = canonicalize(data)

    signature = private_key.sign(payload)

    return base64.b64encode(signature).decode()


def verify_signature(
    public_key_pem: str,
    data: dict,
    signature: str
) -> bool:

    public_key = serialization.load_pem_public_key(
        public_key_pem.encode()
    )

    payload = canonicalize(data)

    signature_bytes = base64.b64decode(signature)

    try:
        public_key.verify(signature_bytes, payload)

        return True

    except Exception:
        return False