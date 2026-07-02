# shared/api/manager/v1/domains.py
"""
Dominio: Domains.

Encapsula la consulta de los dominios a los que pertenece la entidad
autenticada. El servidor solo expone, por ahora, un endpoint de listado
(``query``); este módulo añade ``get_domain`` como utilidad de "detalle"
construida en el lado del cliente (filtrando la lista), ya que el servidor
no expone todavía un endpoint dedicado para un único dominio.

Endpoints cubiertos:
    POST /api/v/1/domains/query
"""

from __future__ import annotations

from typing import List, Optional

from .models import Domain
from .transport import HttpTransport

_PREFIX = "/api/v/1/domains"


class DomainsAPI:
    """API especializada para consultar dominios de OSAM."""

    def __init__(self, transport: HttpTransport) -> None:
        self._transport = transport

    async def query(self, auth_token: str) -> List[Domain]:
        """
        POST /api/v/1/domains/query

        Devuelve la lista de dominios a los que pertenece la entidad
        identificada por ``auth_token``.
        """
        body = await self._transport.post(
            f"{_PREFIX}/query",
            json={"auth_token": auth_token},
        )
        # El servidor devuelve la lista de dominios como cuerpo JSON raíz;
        # HttpTransport la normaliza como {"items": [...]} para mantener
        # una interfaz homogénea (ver HttpTransport._parse_body).
        items = body.get("items", [])
        if not isinstance(items, list):
            items = []
        
        return items

    async def get_domain(
        self, auth_token: str, domain_uid: str
    ) -> Optional[Domain]:
        """
        Utilidad de conveniencia: obtiene un dominio concreto filtrando el
        resultado de :meth:`query`. No existe (todavía) un endpoint de
        servidor dedicado a la consulta de un único dominio.
        """
        domains = await self.query(auth_token)
        print(domains)
        for domain in domains:
            if domain.uid == domain_uid:
                return domain
        return None
