from typing import Dict, Optional

from .credential import AuthenticationCredential


class AuthenticationManager:
    """
    Administra las credenciales de autenticación locales.

    credentials_from
        Credenciales emitidas HACIA esta entidad.

        Índice:
            issuer.uid

        Se utilizan cuando esta entidad desea enviar paquetes
        hacia un peer autenticado.

    credentials_to
        Credenciales emitidas POR esta entidad.

        Índice:
            auth_token

        Se utilizan cuando se recibe un paquete con un
        source_auth_token.
    """

    def __init__(self):

        #
        # Credenciales emitidas hacia nosotros.
        #
        self._credentials_from: Dict[str, AuthenticationCredential] = {}

        #
        # Credenciales emitidas por nosotros.
        #
        self._credentials_to: Dict[str, AuthenticationCredential] = {}

        #
        # Índice auxiliar:
        #
        # subject.uid -> auth_token
        #
        self._credentials_to_uid: Dict[str, str] = {}

    # ---------------------------------------------------------
    # Properties
    # ---------------------------------------------------------

    @property
    def credentials_from(self) -> Dict[str, AuthenticationCredential]:
        return self._credentials_from

    @property
    def credentials_to(self) -> Dict[str, AuthenticationCredential]:
        return self._credentials_to

    # ---------------------------------------------------------
    # Register
    # ---------------------------------------------------------

    def register_from(self, credential: AuthenticationCredential) -> str:
        """
        Registra una credencial emitida hacia esta entidad.

        Índice:
            issuer.uid
        """

        uid = credential.issuer.uid

        self._credentials_from[uid] = credential

        return uid

    def register_to(self, credential: AuthenticationCredential) -> str:
        """
        Registra una credencial emitida por esta entidad.

        Índice principal:
            auth_token

        Índice auxiliar:
            subject.uid
        """

        token = credential.auth_token

        self._credentials_to[token] = credential
        self._credentials_to_uid[credential.subject.uid] = token

        return token

    # ---------------------------------------------------------
    # Resolve
    # ---------------------------------------------------------

    def resolve_from(
        self,
        issuer_uid: str
    ) -> Optional[AuthenticationCredential]:
        """
        Busca la credencial que una entidad emitió hacia nosotros.
        """

        return self._credentials_from.get(issuer_uid)

    def resolve_to(
        self,
        auth_token: str
    ) -> Optional[AuthenticationCredential]:
        """
        Busca una credencial emitida por nosotros utilizando
        el auth_token recibido en un paquete.
        """

        return self._credentials_to.get(auth_token)

    def resolve_to_uid(
        self,
        subject_uid: str
    ) -> Optional[AuthenticationCredential]:
        """
        Busca una credencial emitida por nosotros utilizando
        el UID del subject.
        """

        token = self._credentials_to_uid.get(subject_uid)

        if token is None:
            return None

        return self._credentials_to.get(token)

    # ---------------------------------------------------------
    # Has
    # ---------------------------------------------------------

    def has_from(
        self,
        issuer_uid: str
    ) -> bool:

        return issuer_uid in self._credentials_from

    def has_to(
        self,
        auth_token: str
    ) -> bool:

        return auth_token in self._credentials_to

    # ---------------------------------------------------------
    # Remove
    # ---------------------------------------------------------

    def unregister_from(
        self,
        issuer_uid: str
    ) -> bool:

        return self._credentials_from.pop(
            issuer_uid,
            None
        ) is not None

    def unregister_to(
        self,
        auth_token: str
    ) -> bool:

        credential = self._credentials_to.pop(
            auth_token,
            None
        )

        if credential is None:
            return False

        self._credentials_to_uid.pop(
            credential.subject.uid,
            None
        )

        return True

    # ---------------------------------------------------------
    # Clear
    # ---------------------------------------------------------

    def clear(self) -> None:

        self._credentials_from.clear()
        self._credentials_to.clear()
        self._credentials_to_uid.clear()

    # ---------------------------------------------------------
    # Magic
    # ---------------------------------------------------------

    def __len__(self) -> int:

        return (
            len(self._credentials_from)
            + len(self._credentials_to)
        )

    def __repr__(self):

        return (
            "AuthenticationManager(\n"
            f"    credentials_from={len(self._credentials_from)},\n"
            f"    credentials_to={len(self._credentials_to)}\n"
            ")"
        )