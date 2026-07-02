# shared/api/manager/v1/authentication.py
"""
Dominio: Authentication.

Implementa el protocolo de autenticación por challenge-response (Ed25519)
de OSAM, en sus dos direcciones:

* Autenticación del **cliente** ante el servidor (``client/challenge`` +
  ``verify``): la entidad que llama solicita un reto, lo firma con su clave
  privada y envía la respuesta para que el servidor la valide.
* Autenticación del **servidor** ante el cliente (``server/challenge``):
  el cliente ya posee un ``challenge_id`` (generado en un paso anterior del
  protocolo, fuera del alcance de este módulo) y le pide al servidor que
  produzca su respuesta firmada para poder verificarla localmente.

Endpoints cubiertos (todos bajo ``/api/v/1/auth``):
    POST /client/challenge
    POST /verify
    POST /server/challenge
"""

from __future__ import annotations

from .models import (
    ClientChallenge,
    ClientChallengeVerification,
    ServerChallengeResponse,
)
from .transport import HttpTransport
from ....protocols.negotiation.challenge import ChallengeProtocol, CHALLENGE_TYPE_SERVER_AUTHENTICATION

_PREFIX = "/api/v/1/auth"


class AuthenticationAPI:
    """API especializada para el protocolo de autenticación de OSAM."""

    def __init__(self, transport: HttpTransport) -> None:
        self._transport = transport

    async def create_client_challenge(
        self, entity_uid: str, public_key: str
    ) -> dict:
        """
        POST /api/v/1/auth/client/challenge

        Solicita al servidor un reto de autenticación para la entidad
        identificada por ``entity_uid`` / ``public_key``.
        """
        body = await self._transport.post(
            f"{_PREFIX}/client/challenge",
            json={"entity_uid": entity_uid, "public_key": public_key},
        )

        return ClientChallenge.from_dict(body)

    async def verify_client_challenge(
        self,
        challenge_id: str,
        response: str,
        entity_uid: str,
        public_key: str,
    ) -> ClientChallengeVerification:
        """
        POST /api/v/1/auth/verify

        Envía la respuesta firmada a un reto previamente emitido por
        ``create_client_challenge`` para completar la autenticación.
        """
        body = await self._transport.post(
            f"{_PREFIX}/verify",
            json={
                "challenge_id": challenge_id,
                "response": response,
                "entity_uid": entity_uid,
                "public_key": public_key,
            },
        )
        return body

    async def authenticate_client(self,
        entity_uid: str,
        entity_pik: str,
        entity_ppik: str
    ) -> str:
        # Create challenge
        client_challenge = await self.create_client_challenge(
            entity_uid=entity_uid,
            public_key=entity_pik
        )

        client_challenge_object = ChallengeProtocol.challenge_from_dict(
            client_challenge.challenge
        )

        client_auth_signed = ChallengeProtocol.sign(
            private_key=entity_ppik,
            challenge=client_challenge_object
        )

        response = await self.verify_client_challenge(
            challenge_id=client_challenge.challenge.get("challenge_id"),
            response=ChallengeProtocol.response_to_dict(client_auth_signed),
            entity_uid=entity_uid,
            public_key=entity_pik
        )

        return response

    # =====================================================
    # SERVER AUTHENTICATION
    # =====================================================

    async def register_server_challenge(
        self,
        challenge: dict
    ) -> dict:
        """
        Register challenge in remote server.

        Client -> Server

        POST:
        /api/v/1/auth/server/challenge/register
        """

        body = await self._transport.post(
            f"{_PREFIX}/server/challenge/register",
            json={
                "challenge": challenge
            }
        )

        return body



    async def request_server_response(
        self,
        challenge_id: str
    ) -> dict:
        """
        Request signed challenge response.

        Client -> Server

        POST:
        /api/v/1/auth/server/challenge/response
        """

        body = await self._transport.post(
            f"{_PREFIX}/server/challenge/response",
            json={
                "challenge_id": challenge_id
            }
        )

        return body



    def verify_server_response(
        self,
        challenge: dict,
        response: dict,
        server_public_key: str
    ) -> bool:
        """
        Verify server signature locally.
        """


        challenge_object = (
            ChallengeProtocol.challenge_from_dict(
                challenge
            )
        )


        if not ChallengeProtocol.validate_type(
            challenge_object,
            CHALLENGE_TYPE_SERVER_AUTHENTICATION
        ):

            raise ValueError(
                "Invalid server challenge type"
            )


        response_object = (
            ChallengeProtocol.response_from_dict(
                response["response"]
            )
        )


        return ChallengeProtocol.verify(
            public_key=server_public_key,
            challenge=challenge_object,
            response=response_object
        )



    async def authenticate_server(
        self,
        client_uid: str,
        server_uid: str,
        server_public_key: str
    ) -> bool:
        """
        Authenticate remote server.
        """


        # -----------------------------------------
        # 1. Create challenge
        # -----------------------------------------

        challenge = ChallengeProtocol.create(
            challenge_type=(
                CHALLENGE_TYPE_SERVER_AUTHENTICATION
            ),

            issuer_uid=client_uid,

            target_uid=server_uid
        )


        challenge_dict = (
            ChallengeProtocol.challenge_to_dict(
                challenge
            )
        )


        # -----------------------------------------
        # 2. Register challenge remotely
        # -----------------------------------------

        await self.register_server_challenge(
            challenge_dict
        )


        # -----------------------------------------
        # 3. Ask server signature
        # -----------------------------------------

        response = await self.request_server_response(
            challenge_dict["challenge_id"]
        )


        # -----------------------------------------
        # 4. Verify server proof
        # -----------------------------------------

        verified = (
            self.verify_server_response(
                challenge=challenge_dict,

                response=response,

                server_public_key=server_public_key
            )
        )


        if not verified:

            raise ValueError(
                "Server authentication failed"
            )


        return True