# shared/api/manager/v1/identity.py
"""
Dominio: Identity.

Expone la identidad lógica, criptográfica y de tipo de la entidad que
responde en el otro extremo de la conexión HTTP (típicamente el Manager,
pero el mismo contrato aplica a cualquier entidad OSAM que exponga esta
misma API). Ninguno de estos endpoints requiere autenticación: son el
primer paso antes de iniciar el protocolo de challenge-response.

Endpoints cubiertos (todos bajo ``/api/v/1/identity``):
    GET /logical
    GET /cryptographic
    GET /type
"""

from __future__ import annotations

from .models import CryptographicIdentity, EntityTypeInfo, LogicalIdentity
from .transport import HttpTransport

_PREFIX = "/api/v/1/identity"


class IdentityAPI:
    """API especializada para consultar la identidad de una entidad OSAM."""

    def __init__(self, transport: HttpTransport) -> None:
        self._transport = transport

    async def get_logical_identity(self) -> LogicalIdentity:
        """GET /api/v/1/identity/logical -> identificador lógico (uid)."""
        body = await self._transport.get(f"{_PREFIX}/logical")
        return LogicalIdentity.from_dict(body)

    async def get_cryptographic_identity(self) -> CryptographicIdentity:
        """GET /api/v/1/identity/cryptographic -> identidad criptográfica."""
        body = await self._transport.get(f"{_PREFIX}/cryptographic")
        return CryptographicIdentity.from_dict(body)

    async def get_entity_type(self) -> EntityTypeInfo:
        """GET /api/v/1/identity/type -> tipo de entidad (AGENT/CONSOLE/...)."""
        body = await self._transport.get(f"{_PREFIX}/type")
        return EntityTypeInfo.from_dict(body)
