# shared/api/manager/v1/passports.py
"""
Dominio: Passports.

Encapsula el ciclo de vida de los "pasaportes" OSAM (OPEN / CLOSED), que
son el mecanismo por el cual una entidad ya integrada (típicamente una
CONSOLE) autoriza el ingreso de nuevas entidades a un dominio.

Cobertura real de la API del servidor en esta versión:

* Creación de pasaportes **OPEN**: soportada
  (``POST /api/v/1/passports/open/create``).
* Creación de pasaportes **CLOSED**: NO existe endpoint todavía. Se deja
  ``create_closed`` como punto de extensión explícito.
* "Validación" de un pasaporte: en la API actual, validar un pasaporte y
  consumirlo ocurren en el mismo paso, a través de los endpoints de
  integración (``integrate_open`` / ``integrate_closed``), que reciben el
  ``security_code`` emitido al crear el pasaporte. No existe un endpoint
  de validación "de solo lectura" independiente.
* "Consulta" de pasaportes ya creados: NO existe endpoint todavía. Se deja
  ``get`` como punto de extensión explícito.

Nota importante sobre autenticación de estos endpoints: a diferencia del
resto de la API (que recibe ``auth_token`` en el cuerpo JSON), los
endpoints de integración lo esperan como cabecera ``Authorization: Bearer``.
La SDK respeta esa asimetría: ``HttpTransport`` soporta ambos esquemas y
cada método de este módulo usa el que corresponde según la ruta real.

Endpoints cubiertos:
    POST /api/v/1/passports/open/create   (auth_token en el body)
    POST /api/v/1/integration/open        (auth_token como Bearer token)
    POST /api/v/1/integration/closed      (auth_token como Bearer token)
"""

from __future__ import annotations

from typing import Optional

from .models import IntegrationResult, Passport
from .transport import HttpTransport

_PASSPORTS_PREFIX = "/api/v/1/passports"
_INTEGRATION_PREFIX = "/api/v/1/integration"


class PassportsAPI:
    """API especializada para la gestión de pasaportes OSAM."""

    def __init__(self, transport: HttpTransport) -> None:
        self._transport = transport

    async def create_open(
        self,
        auth_token: str,
        domain_uid: str,
        entity_role: str,
        expiration_hours: int,
        usage_limit: int,
    ) -> Passport:
        """
        POST /api/v/1/passports/open/create

        Crea un pasaporte OPEN para ``domain_uid``, válido para el rol
        ``entity_role``, con expiración y límite de usos indicados.
        Solo entidades CONSOLE integradas pueden invocar esta operación
        (el servidor lo valida; ver ``passports.py`` en las rutas).
        """
        body = await self._transport.post(
            f"{_PASSPORTS_PREFIX}/open/create",
            json={
                "auth_token": auth_token,
                "domain_uid": domain_uid,
                "entity_role": entity_role,
                "expiration_hours": expiration_hours,
                "usage_limit": usage_limit,
            },
        )
        return Passport.from_dict(body.get("passport", {}))

    async def create_closed(self, *args: object, **kwargs: object) -> Passport:
        """
        Punto de extensión: el servidor de OSAM no expone todavía un
        endpoint de creación de pasaportes CLOSED.
        """
        raise NotImplementedError(
            "El servidor de OSAM no expone todavía un endpoint de creación "
            "de pasaportes CLOSED."
        )

    async def integrate_open(
        self, auth_token: str, security_code: str, entity_type: str
    ) -> IntegrationResult:
        """
        POST /api/v/1/integration/open

        Redime un ``security_code`` de un pasaporte OPEN, declarando el
        ``entity_type`` con el que la entidad solicitante se integra.
        ``auth_token`` se envía como cabecera ``Authorization: Bearer``.
        """
        body = await self._transport.post(
            f"{_INTEGRATION_PREFIX}/open",
            json={"security_code": security_code, "entity_type": entity_type},
            bearer_token=auth_token,
        )
        return body

    async def integrate_closed(
        self, auth_token: str, security_code: str
    ) -> IntegrationResult:
        """
        POST /api/v/1/integration/closed

        Redime un ``security_code`` de un pasaporte CLOSED.
        ``auth_token`` se envía como cabecera ``Authorization: Bearer``.
        """
        body = await self._transport.post(
            f"{_INTEGRATION_PREFIX}/closed",
            json={"security_code": security_code},
            bearer_token=auth_token,
        )
        return body

    async def get(self, auth_token: str, passport_uid: str) -> Optional[Passport]:
        """
        Punto de extensión: el servidor de OSAM no expone todavía un
        endpoint de consulta de un pasaporte por identificador.
        """
        raise NotImplementedError(
            "El servidor de OSAM no expone todavía un endpoint de consulta "
            "de pasaportes existentes."
        )
