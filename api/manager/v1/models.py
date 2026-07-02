# shared/api/manager/v1/models.py
"""
Modelos tipados (dataclasses) en los que la SDK convierte las respuestas
JSON crudas de la API HTTP de OSAM.

Nota de transparencia sobre el origen de estos modelos
-------------------------------------------------------
Esta SDK se construyó a partir del código fuente de la capa
``api/http/routes/*.py`` del Manager (no se tuvo acceso al paquete
``core/`` donde viven las implementaciones reales de ``core.auth``,
``core.tunnel``, ``core.session``, ``core.passports``, etc.). Por lo tanto:

* Los campos marcados sin comentario están **confirmados**: se ve
  explícitamente en las rutas que el servidor los lee o los escribe
  (ej. ``entity["entity_uid"]``, ``payload.get("challenge_id")``).
* Los campos marcados con ``# inferido`` son una suposición razonable
  basada en la convención de nombres del propio proyecto (ver
  jerarquía auth_token / session_token / tunnel_token / connection_uid),
  pero no se observaron directamente en el código de rutas.

En ambos casos, cualquier clave adicional que el servidor incluya en la
respuesta y que no esté declarada explícitamente en el dataclass **no se
pierde**: queda disponible en el atributo ``.extra`` (y, en conjunto con los
campos conocidos, a través de ``.raw``). Así, si el equipo de ``core``
cambia o añade un campo, el código que use atributos explícitos sigue
funcionando, y el dato sigue siendo accesible sin tener que actualizar la
SDK de inmediato.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any, ClassVar, Dict, Mapping, Optional, Type, TypeVar

T = TypeVar("T", bound="_BaseModel")


@dataclass
class _BaseModel:
    """
    Clase base para todos los modelos de respuesta de la SDK.

    Provee:
    * ``from_dict``: construye una instancia a partir de un dict JSON,
      asignando las claves conocidas a sus campos declarados y guardando
      el resto en ``extra``.
    * ``raw``: reconstruye el dict completo (campos conocidos + extra),
      útil para depuración/logging sin exponer dicts crudos como tipo de
      retorno habitual de la SDK.
    * ``get``: acceso conveniente a un campo conocido o a ``extra`` sin
      tener que recordar en cuál de los dos vive.
    """

    extra: Dict[str, Any] = field(default_factory=dict, repr=False)

    # Nombre de las claves "id" alternativas que algunas respuestas usan
    # indistintamente (uid / <recurso>_uid). Se usa en from_dict para no
    # duplicar lógica de aliasing en cada subclase.
    _id_aliases: ClassVar[Dict[str, str]] = {}

    @classmethod
    def from_dict(cls: Type[T], data: Mapping[str, Any]) -> T:
        if not isinstance(data, Mapping):
            data = {}

        known_fields = {
            f.name for f in dataclasses.fields(cls) if f.name != "extra"
        }

        working = dict(data)

        # Resuelve alias de identificadores (ej. "uid" -> "passport_uid")
        # sin pisar un valor que ya venga con el nombre canónico.
        for canonical, alias in cls._id_aliases.items():
            if canonical in known_fields and canonical not in working:
                if alias in working:
                    working[canonical] = working[alias]

        kwargs = {k: v for k, v in working.items() if k in known_fields}
        extra = {k: v for k, v in working.items() if k not in known_fields}

        return cls(**kwargs, extra=extra)

    @property
    def raw(self) -> Dict[str, Any]:
        """Devuelve el payload completo (campos tipados + extra) como dict."""
        result = {
            f.name: getattr(self, f.name)
            for f in dataclasses.fields(self)
            if f.name != "extra"
        }
        result.update(self.extra)
        return result

    def get(self, key: str, default: Any = None) -> Any:
        """Acceso conveniente a un campo conocido o a un campo en `extra`."""
        if hasattr(self, key) and key != "extra":
            return getattr(self, key)
        return self.extra.get(key, default)


# =============================================================================
# IDENTITY
# =============================================================================


@dataclass
class LogicalIdentity(_BaseModel):
    """Respuesta de GET /api/v/1/identity/logical."""

    uid: Optional[str] = None


@dataclass
class CryptographicIdentity(_BaseModel):
    """
    Respuesta de GET /api/v/1/identity/cryptographic.

    El endpoint devuelve ``core.get_public_identity()`` sin envoltorio, cuyo
    esquema exacto vive en ``core`` (no incluido en este paquete). Se modelan
    los campos que, de acuerdo a la convención del proyecto (identidad
    criptográfica Ed25519 por entidad), son casi seguros.
    """

    public_key: Optional[str] = None  # inferido
    uid: Optional[str] = None  # inferido
    algorithm: Optional[str] = None  # inferido


@dataclass
class EntityTypeInfo(_BaseModel):
    """Respuesta de GET /api/v/1/identity/type."""

    type: Optional[str] = None


# =============================================================================
# AUTHENTICATION
# =============================================================================


@dataclass
class ClientChallenge(_BaseModel):
    """
    Respuesta de POST /api/v/1/auth/client/challenge.

    Confirmado: la respuesta es ``{"ok": True, **result}`` donde ``result``
    proviene de ``core.auth.create_client_authentication_challenge(...)``.
    El campo ``challenge_id`` es el único que se puede inferir con certeza
    razonable, ya que es el identificador que luego se debe reenviar a
    ``verify_client_challenge``. Cualquier otro dato del reto (nonce, datos a
    firmar, expiración) quedará disponible en ``.extra``.
    """

    ok: Optional[bool] = None
    challenge: Optional[dict] = None


@dataclass
class ClientChallengeVerification(_BaseModel):
    """
    Respuesta de POST /api/v/1/auth/verify.

    Confirmado: ``{"ok": True, **result}`` con ``result`` proveniente de
    ``core.auth.verify_client_authentication(...)``. Tras una verificación
    exitosa, lo esperable es que el servidor emita un ``auth_token`` para la
    entidad (ver jerarquía de tokens del proyecto); se modela como campo
    inferido.
    """

    ok: Optional[bool] = None
    auth_token: Optional[str] = None  # inferido
    uid: Optional[str] = None  # inferido


@dataclass
class ServerChallengeResponse(_BaseModel):
    """
    Respuesta de POST /api/v/1/auth/server/challenge.

    Confirmado: ``{"ok": True, **result}`` con ``result`` proveniente de
    ``core.auth.create_server_authentication_response(challenge_id)``.
    """

    ok: Optional[bool] = None
    response: Optional[Any] = None  # inferido


# =============================================================================
# DOMAINS
# =============================================================================


@dataclass
class Domain(_BaseModel):
    """
    Elemento de la lista devuelta por POST /api/v/1/domains/query.

    El esquema exacto de cada dominio no se observa en las rutas (la lista se
    retorna tal cual la entrega ``core.domain_manager.query_entity_domains``).
    Se modelan los campos más probables según la convención del proyecto.
    """

    _id_aliases: ClassVar[Dict[str, str]] = {"uid": "domain_uid"}

    uid: Optional[str] = None  # inferido (o domain_uid, ver alias)
    name: Optional[str] = None  # inferido
    role: Optional[str] = None  # inferido (rol de membresía del solicitante)


# =============================================================================
# ENTITIES
# =============================================================================


@dataclass
class Entity(_BaseModel):
    """
    Elemento de la lista ``entities`` devuelta por
    POST /api/v/1/entities/agent/query.

    Confirmado en el código de la ruta: cada entidad expone ``entity_uid``,
    y la ruta le añade explícitamente la clave ``status`` (resultado de
    ``core.services.tunnel_service.get_entity_status(...)``).
    """

    entity_uid: Optional[str] = None
    entity_type: Optional[str] = None  # inferido
    status: Optional[Any] = None


# =============================================================================
# PASSPORTS
# =============================================================================


@dataclass
class Passport(_BaseModel):
    """
    Objeto ``passport`` devuelto dentro de
    POST /api/v/1/passports/open/create -> {"created": True, "passport": ...}.

    Confirmado en otras rutas que consumen un passport ya creado: expone al
    menos ``entity_type`` (usado en ``passports.py`` para verificar que solo
    una CONSOLE pueda emitir pasaportes OPEN). El resto de campos son los
    parámetros de creación, que el servidor normalmente devuelve reflejados
    en el objeto creado, más un identificador propio.
    """

    _id_aliases: ClassVar[Dict[str, str]] = {"uid": "passport_uid"}

    uid: Optional[str] = None  # inferido (o passport_uid, ver alias)
    domain_uid: Optional[str] = None  # inferido (eco del parámetro de entrada)
    passport_type: Optional[str] = None  # inferido ("OPEN" / "CLOSED")
    entity_type: Optional[str] = None
    role: Optional[str] = None  # inferido
    expiration_hours: Optional[int] = None  # inferido
    usage_limit: Optional[int] = None  # inferido
    security_code: Optional[str] = None  # inferido (código que luego se usa
    # para "integrar" una entidad vía /integration/open o /integration/closed)


@dataclass
class IntegrationResult(_BaseModel):
    """
    Resultado de POST /api/v/1/integration/open o
    POST /api/v/1/integration/closed.

    El cuerpo de respuesta es completamente opaco desde la capa de rutas
    (se retorna tal cual lo entrega ``core.integration.integrate_open/closed``),
    por lo que no se declaran campos propios más allá de los heredados de
    ``_BaseModel``. Todo el contenido de la respuesta queda en ``.extra`` /
    accesible vía ``.raw``.
    """


# =============================================================================
# SESSIONS
# =============================================================================


@dataclass
class SessionInfo(_BaseModel):
    """
    Respuesta de POST /api/v/1/sessions/request, y forma esperada de cada
    elemento dentro de la lista ``sessions`` de
    POST /api/v/1/sessions/query.

    Confirmado: el envoltorio ``{"ok": True, **result}`` para `/request`.
    El campo ``session_token`` es el identificador central definido por el
    propio proyecto para este recurso.
    """

    ok: Optional[bool] = None
    session_token: Optional[str] = None  # inferido
    tunnel_token: Optional[str] = None  # inferido (eco del parámetro de entrada)
    destination_uid: Optional[str] = None  # inferido (eco del parámetro de entrada)


@dataclass
class SessionDeletionResult(_BaseModel):
    """Respuesta de POST /api/v/1/sessions/delete. Confirmado en su totalidad."""

    ok: Optional[bool] = None
    revoked: Optional[bool] = None
    session_token: Optional[str] = None


# =============================================================================
# TUNNELS
# =============================================================================


@dataclass
class TunnelInfo(_BaseModel):
    """
    Respuesta de POST /api/v/1/services/tunnels/request.

    Confirmado: el envoltorio es
    ``{"ok": True, "tunnel_port": <int>, **result}`` donde ``tunnel_port`` se
    lee literalmente de ``core.services.tunnel_service.ws._port`` en la ruta.
    El resto de campos del ``result`` (lo que retorna
    ``core.tunnel.create_tunnel(auth_token)``) son inferidos según la
    convención de tokens del proyecto.
    """

    ok: Optional[bool] = None
    tunnel_port: Optional[int] = None
    tunnel_token: Optional[str] = None  # inferido
    tunnel_uid: Optional[str] = None  # inferido


@dataclass
class TunnelOperationResult(_BaseModel):
    """
    Resultado de las operaciones legacy/deprecated
    POST /api/v/1/services/tunnels/open y .../link.

    El cuerpo de respuesta es opaco desde la capa de rutas (se retorna tal
    cual lo entrega ``tunnel_service.open_tunnel`` / ``.link_tunnels``).
    """
