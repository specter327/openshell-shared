# shared/api/manager/v1/tunnels.py
"""
Dominio: Tunnels.

Encapsula la solicitud y gestión de túneles. La API actual del servidor
expone:

* ``request`` (vigente): solicita un nuevo túnel asociado a la entidad
  autenticada.
* ``open`` y ``link`` (marcados ``DEPRECATED`` explícitamente en el código
  de las rutas del servidor): se mantienen en la SDK por compatibilidad,
  pero cada llamada emite un ``DeprecationWarning`` para que el código
  consumidor migre al flujo vigente (``request`` + ``sessions``).

No existen (todavía) endpoints de consulta de estado o renovación de un
túnel ya creado; se dejan ``get_status`` y ``renew`` como puntos de
extensión explícitos.

Endpoints cubiertos:
    POST /api/v/1/services/tunnels/request
    POST /api/v/1/services/tunnels/open    (deprecated)
    POST /api/v/1/services/tunnels/link    (deprecated)
"""

from __future__ import annotations

import warnings

from .models import TunnelInfo, TunnelOperationResult
from .transport import HttpTransport

_PREFIX = "/api/v/1/services/tunnels"


class TunnelsAPI:
    """API especializada para la gestión de túneles OSAM."""

    def __init__(self, transport: HttpTransport) -> None:
        self._transport = transport

    async def request(self, auth_token: str) -> dict:
        """
        POST /api/v/1/services/tunnels/request

        Solicita un nuevo túnel para la entidad identificada por
        ``auth_token``. Requiere que la entidad ya pertenezca a, al menos,
        un dominio.
        """
        body = await self._transport.post(
            f"{_PREFIX}/request",
            json={"auth_token": auth_token},
        )
        return body

    async def open(self, session_token: str, tunnel_uid: str) -> dict:
        """
        POST /api/v/1/services/tunnels/open  [DEPRECATED]

        Mantenido por compatibilidad con integraciones existentes. Use
        :meth:`request` seguido del dominio de ``sessions`` en código nuevo.
        """
        warnings.warn(
            "TunnelsAPI.open() llama a un endpoint marcado como DEPRECATED "
            "en el servidor OSAM. Use TunnelsAPI.request() junto con "
            "SessionsAPI.create() en código nuevo.",
            DeprecationWarning,
            stacklevel=2,
        )
        body = await self._transport.post(
            f"{_PREFIX}/open",
            json={"session_token": session_token, "tunnel_uid": tunnel_uid},
        )
        return body

    async def link(
        self,
        session_token: str,
        source_tunnel_uid: str,
        destination_tunnel_uid: str,
    ) -> dict:
        """
        POST /api/v/1/services/tunnels/link  [DEPRECATED]

        Mantenido por compatibilidad con integraciones existentes.
        """
        warnings.warn(
            "TunnelsAPI.link() llama a un endpoint marcado como DEPRECATED "
            "en el servidor OSAM.",
            DeprecationWarning,
            stacklevel=2,
        )
        body = await self._transport.post(
            f"{_PREFIX}/link",
            json={
                "session_token": session_token,
                "source_tunnel_uid": source_tunnel_uid,
                "destination_tunnel_uid": destination_tunnel_uid,
            },
        )
        return body

    async def get_status(self, auth_token: str, tunnel_uid: str) -> TunnelInfo:
        """
        Punto de extensión: el servidor de OSAM no expone todavía un
        endpoint dedicado de consulta de estado de un túnel existente.
        """
        raise NotImplementedError(
            "El servidor de OSAM no expone todavía un endpoint de consulta "
            "de estado de túneles."
        )

    async def renew(self, auth_token: str, tunnel_uid: str) -> TunnelInfo:
        """
        Punto de extensión: el servidor de OSAM no expone todavía un
        endpoint de renovación de un túnel existente.
        """
        raise NotImplementedError(
            "El servidor de OSAM no expone todavía un endpoint de "
            "renovación de túneles."
        )
