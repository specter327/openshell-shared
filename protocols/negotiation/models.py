from dataclasses import dataclass


@dataclass
class AuthenticationChallenge:
    schema: int

    challenge_type: str

    challenge_id: str

    issuer_uid: str
    target_uid: str

    nonce: str

    issued_at: int
    expires_at: int

@dataclass
class AuthenticationResponse:
    schema: int

    challenge_id: str

    responder_uid: str

    signature: str