# shared/api/manager/v1/exceptions.py
"""
Jerarquía de excepciones de la SDK de OSAM.

Diseño:

    OSAMError                  -> raíz de toda excepción producida por la SDK
    ├── NetworkError           -> fallos de transporte (timeout, DNS, conexión rechazada...)
    ├── InvalidResponseError   -> el servidor respondió pero el cuerpo no es JSON
    │                            válido o no contiene los campos esperados
    └── APIError               -> el servidor respondió con un código de error HTTP
        ├── ValidationError        (400 / 422 - payload inválido o incompleto)
        ├── AuthenticationError    (401 - token/credencial inválida o ausente)
        ├── AuthorizationError     (403 - la entidad no tiene permiso sobre el recurso)
        ├── EntityNotFoundError    (404 - el recurso solicitado no existe)
        └── ServerError            (5xx - error interno del servidor OSAM)

Ningún método de la SDK debe propagar excepciones de ``httpx`` ni errores
ambiguos (``KeyError``, ``ValueError`` genéricos, etc.) hacia el código que
consume la librería. Toda esa traducción ocurre en ``transport.py``.
"""

from __future__ import annotations

from typing import Any, Optional


class OSAMError(Exception):
    """Excepción base de la SDK de OSAM. Todo error propio hereda de esta clase."""

    def __init__(self, message: str, *, detail: Optional[Any] = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail

    def __str__(self) -> str:  # pragma: no cover - cosmético
        if self.detail is not None and str(self.detail) != self.message:
            return f"{self.message} (detail={self.detail!r})"
        return self.message


class NetworkError(OSAMError):
    """
    La petición no pudo completarse a nivel de transporte: timeout, host
    inalcanzable, conexión rechazada, error de DNS, error de TLS, etc.

    No hubo respuesta HTTP que interpretar; el problema es la red o el
    servidor remoto está caído/inaccesible.
    """


class InvalidResponseError(OSAMError):
    """
    El servidor respondió, pero el contenido no se pudo interpretar como se
    esperaba: JSON malformado, o ausencia de campos que la SDK considera
    obligatorios para construir el modelo de respuesta correspondiente.
    """


class APIError(OSAMError):
    """
    Clase base para errores reportados explícitamente por la API mediante un
    código de estado HTTP de error. Contiene siempre el código de estado y,
    si estuvo disponible, el cuerpo de error devuelto por el servidor (que en
    OSAM sigue el formato estándar de FastAPI: ``{"detail": ...}``).
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        detail: Optional[Any] = None,
        response_body: Optional[Any] = None,
    ) -> None:
        super().__init__(message, detail=detail)
        self.status_code = status_code
        self.response_body = response_body


class ValidationError(APIError):
    """400 / 422 — la petición enviada por el cliente es inválida o incompleta."""


class AuthenticationError(APIError):
    """401 — token de autenticación ausente, inválido o expirado."""


class AuthorizationError(APIError):
    """403 — la entidad autenticada no tiene permisos sobre el recurso solicitado."""


class EntityNotFoundError(APIError):
    """404 — el recurso solicitado (entidad, dominio, sesión...) no existe."""


class ServerError(APIError):
    """5xx — error interno no controlado dentro del servidor OSAM."""
