# shared/api/manager/v1/entities.py
"""
Dominio: Entities.

Encapsula la consulta de entidades visibles para el solicitante. La API
actual del servidor solo expone consulta de entidades de tipo ``AGENT``
(``/entities/agent/query``); no existe todavía un endpoint genérico por
tipo arbitrario ni un filtro por dominio. Este módulo expone:

* ``query_agents``: llamada directa al único endpoint real disponible.
* ``query``: punto de extensión genérico preparado para cuando el servidor
  exponga más tipos de entidad; hoy delega en ``query_agents`` para
  ``entity_type in (None, "AGENT")`` y lanza ``NotImplementedError`` para
  cualquier otro valor, dejando explícito qué falta en el servidor.
* ``query_by_domain``: punto de extensión, no soportado aún por el servidor.
* ``get_agent``: utilidad de conveniencia que filtra del lado del cliente.

Endpoints cubiertos:
    POST /api/v/1/entities/agent/query
"""

from __future__ import annotations

from typing import List, Optional

from .models import Entity
from .transport import HttpTransport

_PREFIX = "/api/v/1/entities"


class EntitiesAPI:
    """API especializada para consultar entidades visibles en OSAM."""

    def __init__(self, transport: HttpTransport) -> None:
        self._transport = transport

    async def query_agents(self, auth_token: str) -> list:
        """
        POST /api/v/1/entities/agent/query

        Devuelve las entidades de tipo AGENT visibles para la entidad
        identificada por ``auth_token``, cada una con su ``status`` de
        túnel actual.
        """
        body = await self._transport.post(
            f"{_PREFIX}/agent/query",
            json={"auth_token": auth_token},
        )
        entities = body.get("entities", [])
        if not isinstance(entities, list):
            entities = []
        return entities

    async def query(
        self, auth_token: str, entity_type: Optional[str] = None
    ) -> list:
        """
        Punto de extensión genérico por tipo de entidad.

        Actualmente el servidor solo soporta ``entity_type in (None, "AGENT")``;
        cualquier otro valor lanza ``NotImplementedError`` de forma explícita
        en vez de devolver un resultado vacío silencioso.
        """
        if entity_type not in (None, "AGENT"):
            raise NotImplementedError(
                "El servidor de OSAM solo expone consulta de entidades "
                "AGENT en esta versión de la API "
                "(/api/v/1/entities/agent/query). "
                f"entity_type={entity_type!r} no está soportado todavía."
            )
        return await self.query_agents(auth_token)

    async def query_by_domain(self, auth_token: str, domain_uid: str) -> List[Entity]:
        """
        Punto de extensión: el servidor no expone (todavía) filtrado de
        entidades por dominio. Queda declarado aquí para que, cuando se
        añada el endpoint correspondiente, solo haya que actualizar la
        implementación de este método sin tocar el resto de la SDK.
        """
        raise NotImplementedError(
            "El servidor de OSAM no expone todavía un endpoint de consulta "
            "de entidades filtrado por dominio."
        )

    async def get_agent(
        self, auth_token: str, entity_uid: str
    ) -> Optional[Entity]:
        """
        Utilidad de conveniencia: obtiene un AGENT concreto filtrando el
        resultado de :meth:`query_agents` del lado del cliente.
        """
        agents = await self.query_agents(auth_token)
        for agent in agents:
            if agent.entity_uid == entity_uid:
                return agent
        return None
