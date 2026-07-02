# shared/api/manager/v1/client.py
"""
Cliente principal de la SDK de OSAM.

``OSAMClient`` es el único punto de entrada que el resto del sistema
(OpenShell Console, OpenShell Agent, futuras GUIs, herramientas
automatizadas) debe usar para hablar con la API HTTP de OSAM. Internamente
compone una única instancia de ``HttpTransport`` (la capa HTTP real) y la
inyecta en cada API de dominio especializada.

No hay estado global ni singletons: cada instancia de ``OSAMClient``
representa una conexión independiente a un host:puerto concreto, y puede
crearse tantas veces como se necesite (por ejemplo, una Console que habla
simultáneamente con el Manager y, en el futuro, con un Agent expuesto en
otro host).

Ejemplo de uso::

    import asyncio
    from shared.api.manager.v1 import OSAMClient

    async def main():
        async with OSAMClient(host="fortaprest.org", port=8000, protocol="https") as client:
            identity = await client.identity.get_logical_identity()
            print(identity.uid)

    asyncio.run(main())
"""

from __future__ import annotations

import logging
from typing import Union

from .authentication import AuthenticationAPI
from .domains import DomainsAPI
from .entities import EntitiesAPI
from .identity import IdentityAPI
from .passports import PassportsAPI
from .sessions import SessionsAPI
from .transport import HttpTransport
from .tunnels import TunnelsAPI

logger = logging.getLogger("osam.client")

_VALID_PROTOCOLS = ("http", "https")


class OSAMClient:
    """
    Cliente de alto nivel para la API HTTP de OSAM.

    Args:
        host: Host o IP del servidor OSAM (Manager, normalmente).
        port: Puerto HTTP/HTTPS de la API.
        protocol: ``"http"`` o ``"https"``. Use ``"https"`` en producción;
            el endurecimiento TLS del proyecto vive en el lado del servidor
            (ver variables ``OSAM_MANAGER_HOST`` / ``OSAM_CA_BUNDLE``), esta
            SDK solo necesita saber qué esquema usar y, opcionalmente, qué
            bundle de CA validar contra él.
        timeout: Timeout en segundos aplicado a cada petición HTTP.
        verify_ssl: ``True``/``False`` para activar/desactivar la
            verificación TLS, o una ruta a un bundle de CA personalizado
            (equivalente al parámetro ``verify`` de ``httpx``). Útil para
            apuntar a ``OSAM_CA_BUNDLE`` durante el endurecimiento HTTPS.

    Atributos expuestos (una instancia por dominio funcional):
        identity, authentication, domains, tunnels, sessions, passports,
        entities.
    """

    def __init__(
        self,
        host: str,
        port: int,
        protocol: str = "http",
        *,
        timeout: float = 10.0,
        verify_ssl: Union[bool, str] = True,
    ) -> None:
        if protocol not in _VALID_PROTOCOLS:
            raise ValueError(
                f"protocol debe ser uno de {_VALID_PROTOCOLS!r}, recibido {protocol!r}"
            )

        base_url = f"{protocol}://{host}:{port}"
        logger.debug("Inicializando OSAMClient hacia %s", base_url)

        self._transport = HttpTransport(
            base_url=base_url,
            timeout=timeout,
            verify_ssl=verify_ssl,
        )

        self.identity = IdentityAPI(self._transport)
        self.authentication = AuthenticationAPI(self._transport)
        self.domains = DomainsAPI(self._transport)
        self.tunnels = TunnelsAPI(self._transport)
        self.sessions = SessionsAPI(self._transport)
        self.passports = PassportsAPI(self._transport)
        self.entities = EntitiesAPI(self._transport)

    async def close(self) -> None:
        """Cierra las conexiones HTTP subyacentes. Idempotente."""
        await self._transport.aclose()

    async def __aenter__(self) -> "OSAMClient":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()
