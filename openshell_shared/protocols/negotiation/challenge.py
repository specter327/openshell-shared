# shared/protocols/negotiation/challenge.py

import json
import secrets
from time import time
from uuid6 import uuid7

from .models import AuthenticationChallenge, AuthenticationResponse
from ...cryptography.signatures import sign_data, verify_signature


SCHEMA_VERSION = 1

CHALLENGE_TYPE_SERVER_AUTHENTICATION = "server_authentication"
CHALLENGE_TYPE_CLIENT_AUTHENTICATION = "client_authentication"


class ChallengeProtocol:

    # -----------------------------
    # SERIALIZATION CANÓNICA
    # -----------------------------
    @staticmethod
    def _serialize(data: dict) -> dict:
        return json.loads(
            json.dumps(data, sort_keys=True, separators=(",", ":"))
        )

    @staticmethod
    def _challenge_payload(challenge: AuthenticationChallenge) -> dict:
        # SOLO campos relevantes para firma (CRÍTICO)
        return ChallengeProtocol._serialize({
            "schema": challenge.schema,
            "challenge_type": challenge.challenge_type,
            "challenge_id": challenge.challenge_id,
            "issuer_uid": challenge.issuer_uid,
            "target_uid": challenge.target_uid,
            "nonce": challenge.nonce,
            "issued_at": challenge.issued_at,
            "expires_at": challenge.expires_at,
        })

    # -----------------------------
    # CREACIÓN
    # -----------------------------
    @staticmethod
    def create(challenge_type: str, issuer_uid: str, target_uid: str, expires_in: int = 60):
        now = int(time())

        return AuthenticationChallenge(
            schema=SCHEMA_VERSION,
            challenge_type=challenge_type,
            challenge_id=str(uuid7()),
            issuer_uid=issuer_uid,
            target_uid=target_uid,
            nonce=secrets.token_hex(32),
            issued_at=now,
            expires_at=now + expires_in
        )

    # -----------------------------
    # FIRMA
    # -----------------------------
    @staticmethod
    def sign(private_key: str, challenge: AuthenticationChallenge) -> AuthenticationResponse:
        payload = ChallengeProtocol._challenge_payload(challenge)

        signature = sign_data(private_key, payload)

        return AuthenticationResponse(
            schema=SCHEMA_VERSION,
            challenge_id=challenge.challenge_id,
            responder_uid=challenge.target_uid,
            signature=signature
        )

    # -----------------------------
    # VERIFICACIÓN
    # -----------------------------
    @staticmethod
    def verify(public_key: str, challenge: AuthenticationChallenge, response: AuthenticationResponse) -> bool:
        payload = ChallengeProtocol._challenge_payload(challenge)
        return verify_signature(public_key, payload, response.signature)

    # -----------------------------
    # UTILIDADES
    # -----------------------------
    @staticmethod
    def is_expired(challenge) -> bool:
        return int(time()) > challenge.expires_at

    @staticmethod
    def validate_type(challenge, expected_type: str) -> bool:
        return challenge.challenge_type == expected_type

    # -----------------------------
    # SERIALIZACIÓN ROBUSTA
    # -----------------------------
    @staticmethod
    def challenge_to_dict(challenge) -> dict:
        return {
            "schema": challenge.schema,
            "challenge_type": challenge.challenge_type,
            "challenge_id": challenge.challenge_id,
            "issuer_uid": challenge.issuer_uid,
            "target_uid": challenge.target_uid,
            "nonce": challenge.nonce,
            "issued_at": challenge.issued_at,
            "expires_at": challenge.expires_at,
        }

    @staticmethod
    def response_to_dict(response) -> dict:
        return {
            "schema": response.schema,
            "challenge_id": response.challenge_id,
            "responder_uid": response.responder_uid,
            "signature": response.signature,
        }

    @staticmethod
    def challenge_from_dict(data: dict):
        return AuthenticationChallenge(**data)

    @staticmethod
    def response_from_dict(data: dict):
        return AuthenticationResponse(**data)