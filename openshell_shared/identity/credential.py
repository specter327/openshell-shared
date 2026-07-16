import json
import time
import base64
from uuid6 import uuid7
from typing import Dict, Any
from cryptography.exceptions import InvalidSignature
from .entity import EntityIdentity

class AuthenticationCredential:
    """
    Representa una estructura de credencial firmada digitalmente.
    Garantiza la integridad de los datos de autenticación vinculando al emisor 
    y al sujeto mediante sus atributos criptográficos inmutables (UID y PIK).
    """
    def __repr__(self) -> str:
        return (
            "AuthenticationCredential(\n"
            f"    auth_token={self._auth_token},\n"
            f"    authenticated_at={self._authenticated_at},\n"
            f"    issuer={self._issuer},\n"
            f"    subject={self._subject}\n"
            ")"
        )

    def __init__(
        self,
        auth_token: str,
        authenticated_at: int,
        issuer: "EntityIdentity",
        subject: "EntityIdentity",
        signature: bytes
    ):
        self._auth_token = auth_token
        self._authenticated_at = authenticated_at
        self._issuer = issuer
        self._subject = subject
        self._signature = signature

    @property
    def auth_token(self) -> str:
        return self._auth_token

    @property
    def authenticated_at(self) -> int:
        return self._authenticated_at

    @property
    def issuer(self) -> "EntityIdentity":
        return self._issuer

    @property
    def subject(self) -> "EntityIdentity":
        return self._subject

    @property
    def signature(self) -> bytes:
        return self._signature

    @property
    def is_valid(self) -> bool:
        return self.validate()

    def _compute_canonical_payload(self) -> bytes:
        """
        Construye una representación binaria determinista de la credencial.
        Aísla el payload de los retos temporales, incluyendo únicamente
        las identidades estructurales (uid y pik) de las entidades.
        """
        payload = {
            "auth_token": self._auth_token,
            "authenticated_at": self._authenticated_at,
            "issuer": {
                "uid": self._issuer.uid,
                "pik": base64.b64encode(self._issuer.pik).decode("utf-8")
            },
            "subject": {
                "uid": self._subject.uid,
                "pik": base64.b64encode(self._subject.pik).decode("utf-8")
            }
        }
        # Serialización canónica estricta (llaves ordenadas, sin espacios)
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @classmethod
    def create(cls, subject: "EntityIdentity", issuer: "EntityIdentity") -> "AuthenticationCredential":
        """
        Instancia una nueva credencial de autenticación y genera su firma criptográfica.
        El token generado utiliza el estándar UUIDv7 de OpenShell.
        """
        auth_token = str(uuid7())
        authenticated_at = int(time.time())

        instance = cls(
            auth_token=auth_token,
            authenticated_at=authenticated_at,
            issuer=issuer,
            subject=subject,
            signature=b""
        )

        # El emisor firma el bloque de datos que contiene las estructuras estáticas
        canonical_data = instance._compute_canonical_payload()
        instance._signature = issuer.sign(canonical_data)
        
        return instance

    def validate(self) -> bool:
        """
        Verifica la autenticidad matemática de la credencial.
        Inmune a la mutación o expiración de los desafíos internos de las identidades.
        """
        try:
            canonical_data = self._compute_canonical_payload()

            # Verificación asimétrica directa usando la clave pública del emisor
            return self._issuer.verify_sign(
                data=canonical_data,
                pik=self._issuer.pik,
                signature=self._signature
            )
        except (InvalidSignature, ValueError, TypeError, KeyError):
            return False

    # ---------------------------------------------------------
    # Serialization
    # ---------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """
        Exporta la credencial a un diccionario.
        """

        return {
            "auth_token": self._auth_token,
            "authenticated_at": self._authenticated_at,
            "issuer": self._issuer.to_dict(
                include_private=False
            ),
            "subject": self._subject.to_dict(
                include_private=False
            ),
            "signature": base64.b64encode(
                self._signature
            ).decode("utf-8")
        }


    @classmethod
    def from_dict(
        cls,
        data: Dict[str, Any]
    ) -> "AuthenticationCredential":
        """
        Reconstruye una credencial desde un diccionario.
        """
        issuer = EntityIdentity.from_dict(
            data["issuer"]
        )


        subject = EntityIdentity.from_dict(
            data["subject"]
        )

        # Validate both identites
        if not issuer.validate():
            raise ValueError(f"Invalid issuer: {issuer}")

        if not subject.validate():
            raise ValueError(f"Invalid subject: {subject}")

        signature = base64.b64decode(
            data["signature"]
        )

        credential = cls(
            auth_token=data["auth_token"],
            authenticated_at=data["authenticated_at"],
            issuer=issuer,
            subject=subject,
            signature=signature
        )

        if not credential.validate():
            raise ValueError(f"Invalid credential")

        return credential 


    def to_json(self) -> str:
        """
        Serializa la credencial a JSON.
        """

        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":")
        )


    @classmethod
    def from_json(
        cls,
        data: str
    ) -> "AuthenticationCredential":
        """
        Reconstruye una credencial desde JSON.
        """

        return cls.from_dict(
            json.loads(data)
        )