# shared/api/manager/v1/transport.py
"""
Capa de transporte HTTP centralizada de la SDK de OSAM.

``HttpTransport`` es el único lugar del paquete que sabe construir URLs,
serializar/deserializar JSON, aplicar timeouts y traducir respuestas HTTP
de error en excepciones propias de la SDK (ver ``exceptions.py``).

Ningún otro módulo de ``shared/api/manager/v1`` debe importar ``httpx`` directamente
ni construir URLs a mano: todos los módulos de dominio (``identity.py``,
``authentication.py``, ``domains.py``, etc.) reciben una instancia de
``HttpTransport`` y delegan en ella toda la comunicación de red.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Mapping, Optional, Union

import httpx

from .exceptions import (
    APIError,
    AuthenticationError,
    AuthorizationError,
    EntityNotFoundError,
    InvalidResponseError,
    NetworkError,
    ServerError,
    ValidationError,
)

logger = logging.getLogger("osam.transport")


def _mask_secret(value: Optional[str], keep: int = 4) -> str:
    """
    Devuelve una versión enmascarada de un secreto (token, código, etc.)
    apta para logging. Nunca se debe registrar un token completo.
    """
    if not value:
        return "<empty>"
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}...{value[-keep:]}"


def _extract_detail(body: Any) -> str:
    """
    Extrae un mensaje legible del cuerpo de error de FastAPI.

    FastAPI usa de forma consistente el formato ``{"detail": ...}``.
    ``detail`` normalmente es un string (HTTPException explícita) pero en
    errores de validación de pydantic (422) puede ser una lista de objetos
    ``{"loc": ..., "msg": ..., "type": ...}``.
    """
    if isinstance(body, Mapping):
        detail = body.get("detail")
        if isinstance(detail, str):
            return detail
        if isinstance(detail, list):
            parts = []
            for item in detail:
                if isinstance(item, Mapping) and "msg" in item:
                    loc = ".".join(str(p) for p in item.get("loc", []))
                    parts.append(f"{loc}: {item['msg']}" if loc else str(item["msg"]))
                else:
                    parts.append(str(item))
            if parts:
                return "; ".join(parts)
        if detail is not None:
            return str(detail)
    return "Error desconocido devuelto por el servidor OSAM"


class HttpTransport:
    """
    Cliente HTTP interno y de bajo nivel usado por toda la SDK.

    Responsabilidades:
    * Mantener la URL base (protocolo + host + puerto).
    * Aplicar timeouts y verificación TLS de forma consistente.
    * Serializar el cuerpo de la petición y deserializar la respuesta JSON.
    * Traducir errores de red y códigos HTTP de error en la jerarquía de
      excepciones de ``exceptions.py``.

    No conoce nada sobre los dominios funcionales de OSAM (identidad,
    pasaportes, túneles...); eso vive en los módulos de dominio que
    consumen esta clase.
    """

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 10.0,
        verify_ssl: Union[bool, str] = True,
        default_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=timeout,
            verify=verify_ssl,
            headers=default_headers or {},
        )

    # -- ciclo de vida -----------------------------------------------------

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "HttpTransport":
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        await self.aclose()

    # -- API pública usada por los módulos de dominio -----------------------

    async def get(
        self,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        bearer_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        return await self._request(
            "GET", path, params=params, bearer_token=bearer_token
        )

    async def post(
        self,
        path: str,
        *,
        json: Optional[Mapping[str, Any]] = None,
        bearer_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        return await self._request(
            "POST", path, json=json, bearer_token=bearer_token
        )

    # -- internals ----------------------------------------------------------

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Mapping[str, Any]] = None,
        params: Optional[Mapping[str, Any]] = None,
        bearer_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        headers: Dict[str, str] = {}
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"

        logger.debug(
            "OSAM %s %s%s (bearer=%s)",
            method,
            self._base_url,
            path,
            _mask_secret(bearer_token),
        )

        try:
            response = await self._client.request(
                method,
                path,
                json=dict(json) if json is not None else None,
                params=dict(params) if params is not None else None,
                headers=headers,
            )
        except httpx.TimeoutException as exc:
            raise NetworkError(
                f"Tiempo de espera agotado al llamar a {method} {path}"
            ) from exc
        except httpx.TransportError as exc:
            raise NetworkError(
                f"No se pudo establecer comunicación con el servidor OSAM "
                f"({method} {path}): {exc}"
            ) from exc

        body = self._parse_body(response, method, path)

        if response.is_success:
            return body

        # _raise_for_status siempre lanza una subclase de APIError.
        self._raise_for_status(response.status_code, body, method, path)
        raise AssertionError("unreachable")  # pragma: no cover

    @staticmethod
    def _parse_body(
        response: httpx.Response, method: str, path: str
    ) -> Dict[str, Any]:
        if not response.content:
            return {}
        try:
            data = response.json()
        except ValueError as exc:
            raise InvalidResponseError(
                f"Respuesta no es JSON válido para {method} {path} "
                f"(status={response.status_code})"
            ) from exc

        if isinstance(data, dict):
            return data
        if isinstance(data, list):
            # Algunos endpoints (ej. /domains/query) devuelven una lista
            # cruda en lugar de un objeto. Se envuelve para mantener una
            # interfaz homogénea hacia el resto de la SDK.
            return {"items": data}

        raise InvalidResponseError(
            f"Respuesta JSON con forma inesperada para {method} {path}: "
            f"se esperaba un objeto o una lista, se obtuvo {type(data).__name__}"
        )

    @staticmethod
    def _raise_for_status(
        status_code: int, body: Dict[str, Any], method: str, path: str
    ) -> None:
        detail = _extract_detail(body)
        message = f"{method} {path} -> HTTP {status_code}: {detail}"

        if status_code in (400, 422):
            raise ValidationError(
                message, status_code=status_code, detail=detail, response_body=body
            )
        if status_code == 401:
            raise AuthenticationError(
                message, status_code=status_code, detail=detail, response_body=body
            )
        if status_code == 403:
            raise AuthorizationError(
                message, status_code=status_code, detail=detail, response_body=body
            )
        if status_code == 404:
            raise EntityNotFoundError(
                message, status_code=status_code, detail=detail, response_body=body
            )
        if status_code >= 500:
            raise ServerError(
                message, status_code=status_code, detail=detail, response_body=body
            )

        # Cualquier otro código de error no contemplado explícitamente por
        # la API de OSAM cae en el caso genérico, sin perder información.
        raise APIError(
            message, status_code=status_code, detail=detail, response_body=body
        )

