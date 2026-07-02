# shared/api/manager/v1/sessions.py
"""
Dominio: Sessions.

Encapsula la creación, listado y cierre de sesiones de shell sobre un
túnel ya establecido.

Endpoints cubiertos (todos bajo ``/api/v/1/sessions``):
    POST /request
    POST /query
    POST /delete
"""

from __future__ import annotations

from typing import List

from .models import SessionDeletionResult, SessionInfo
from .transport import HttpTransport

_PREFIX = "/api/v/1/sessions"


class SessionsAPI:
    """API especializada para la gestión de sesiones OSAM."""

    def __init__(self, transport: HttpTransport) -> None:
        self._transport = transport

    async def create(
        self, auth_token: str, tunnel_token: str, destination_uid: str
    ) -> dict:
        """
        POST /api/v/1/sessions/request

        Crea una nueva sesión sobre el túnel ``tunnel_token`` hacia la
        entidad destino ``destination_uid``.
        """
        body = await self._transport.post(
            f"{_PREFIX}/request",
            json={
                "auth_token": auth_token,
                "tunnel_token": tunnel_token,
                "destination_uid": destination_uid,
            },
        )
        return body

    async def list(self, auth_token: str, tunnel_token: str) -> list:
        """
        POST /api/v/1/sessions/query

        Lista las sesiones activas. Nota: el servidor exige ``tunnel_token``
        en el payload (forma parte del modelo de request), aunque la
        implementación actual del handler no lo use para filtrar — se envía
        igualmente para cumplir el contrato HTTP exacto del servidor.
        """
        body = await self._transport.post(
            f"{_PREFIX}/query",
            json={"auth_token": auth_token, "tunnel_token": tunnel_token},
        )
        sessions = body.get("sessions", [])
        if not isinstance(sessions, list):
            sessions = []
        return sessions

    async def close(
        self, auth_token: str, tunnel_token: str, session_token: str
    ) -> dict:
        """
        POST /api/v/1/sessions/delete

        Revoca la sesión identificada por ``session_token``.
        """
        body = await self._transport.post(
            f"{_PREFIX}/delete",
            json={
                "auth_token": auth_token,
                "tunnel_token": tunnel_token,
                "session_token": session_token,
            },
        )
        return body
