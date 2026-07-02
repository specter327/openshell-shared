# OpenShell Shared

Librería compartida usada por los componentes de OpenShell (OSAM, OSA, OSAC).

Contiene:

- **identity/** — Identidad lógica de las entidades (`EntityIdentity`, `Identification`) y su
  persistencia (`store.py`).
- **cryptography/** — Primitivas Ed25519 (`keys.py`, `signatures.py`), identidad criptográfica
  (`identity.py`) y certificados (`certificate.py`). `encoding.py` y `utils.py` son módulos
  reservados para trabajo futuro (actualmente sin implementación).
- **protocols/negotiation/** — Protocolo de challenge-response (`challenge.py`) y sus modelos.
- **domain/** — Modelo de dominio (`Domain`, `Membership`, `Permission`) y políticas de
  autorización. `policies.py` es un stub pendiente de implementación real.
- **standards/** — Enumeraciones y contratos compartidos entre componentes: tipos de entidad,
  certificados, eventos, roles, permisos, passports y transportes.
- **modules/shell/** — Implementación del subsistema de shell remoto (cliente, servidor, sesión
  y protocolo de framing) usado por OSA y OSAC.
- **api/manager/v1/** — SDK oficial async para consumir la API HTTP de OSAM (`OSAMClient`).
  Todo el sistema (OSAC, OSA, herramientas internas) debe consumir OSAM exclusivamente a través
  de este paquete; ningún otro componente debe importar `httpx`/`requests` directamente para
  hablar con OSAM.

## Notas de la fusión (v2.1.0)

Esta versión unifica dos ramas que habían divergido:

- Se conserva la estructura de empaquetado (`pyproject.toml`, layout `src`) y los módulos
  `domain/` y `standards/`, introducidos en la rama de refactor v2.
- Se restaura `modules/shell/` y se sustituye el cliente HTTP monolítico
  (`api/manager/1/osam_client.py`) por el SDK modular (`api/manager/v1/`), que es la versión
  vigente y más completa (excepciones tipadas, dataclasses, suite de tests con mock transport).

### Deuda técnica pendiente identificada durante la fusión

1. `domain/permissions.py` y `standards/permissions/types.py` definen dos enums `Permission`
   distintos y no compatibles entre sí (`AGENT_READ/AGENT_EXECUTE/DOMAIN_ADMIN/PROXY_USE` vs.
   `DOMAIN_READ/DOMAIN_WRITE/ENTITY_REGISTER/ENTITY_REVOKE/PROXY_USE`). No se han unificado
   automáticamente porque implica una decisión de diseño (cuál es la fuente de verdad de
   permisos). Requiere consolidación manual.
2. `cryptography/encoding.py`, `cryptography/utils.py` y `domain/policies.py` son placeholders
   vacíos o triviales (`Policy.evaluate` siempre retorna `True`). No implementan lógica real.
3. El SDK (`api/manager/v1/`) no reexpone los helpers de alto nivel `full_connect` /
   `open_and_link` que existían en el cliente monolítico anterior (composición de
   autenticación + túnel + sesión en una sola llamada). Si se siguen usando, conviene
   reimplementarlos como métodos de conveniencia sobre `OSAMClient`.
