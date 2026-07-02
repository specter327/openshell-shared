# shared/api/manager/v1/__init__.py
"""
SDK oficial de Python para consumir la API HTTP de OpenShell Access
Manager (OSAM).

Uso típico::

    from shared.api.manager.v1 import OSAMClient

    async with OSAMClient(host="...", port=8000, protocol="https") as client:
        ...

Todo el sistema (OpenShell Console, OpenShell Agent, GUIs, herramientas
automatizadas) debe consumir OSAM exclusivamente a través de este paquete;
ningún otro componente debe importar ``httpx``/``requests`` directamente
para hablar con OSAM.
"""

from .client import OSAMClient
from .exceptions import (
    APIError,
    AuthenticationError,
    AuthorizationError,
    EntityNotFoundError,
    InvalidResponseError,
    NetworkError,
    OSAMError,
    ServerError,
    ValidationError,
)
from .models import (
    ClientChallenge,
    ClientChallengeVerification,
    CryptographicIdentity,
    Domain,
    Entity,
    EntityTypeInfo,
    IntegrationResult,
    LogicalIdentity,
    Passport,
    ServerChallengeResponse,
    SessionDeletionResult,
    SessionInfo,
    TunnelInfo,
    TunnelOperationResult,
)

__all__ = [
    # Cliente principal
    "OSAMClient",
    # Excepciones
    "OSAMError",
    "NetworkError",
    "InvalidResponseError",
    "APIError",
    "ValidationError",
    "AuthenticationError",
    "AuthorizationError",
    "EntityNotFoundError",
    "ServerError",
    # Modelos
    "LogicalIdentity",
    "CryptographicIdentity",
    "EntityTypeInfo",
    "ClientChallenge",
    "ClientChallengeVerification",
    "ServerChallengeResponse",
    "Domain",
    "Entity",
    "Passport",
    "IntegrationResult",
    "SessionInfo",
    "SessionDeletionResult",
    "TunnelInfo",
    "TunnelOperationResult",
]

__version__ = "0.1.0"
