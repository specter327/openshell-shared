import os
import time
import struct
import json
import base64
import hashlib
from uuid6 import uuid7
from typing import Optional, Dict, Any
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

class Identity:
    """
    Representa una identidad criptográfica autocontenida y transportable.
    Abstrae el manejo de claves Ed25519, la generación de UUIDv7 y la 
    validación de desafíos basados en tiempo y noce criptográfica.
    """
    
    # Ventana de tiempo estándar para la validez del desafío (5 minutos)
    CHALLENGE_TTL_SECONDS: int = 300

    def __repr__(self):
        return f"Identity(\n    uid='{self.uid}',\n    algorithm={self.algorithm},\n    pik_fingerprint={self.pik_fingerprint},\n    local={self.is_local}\n)"

    def __init__(
        self, 
        uid: str, 
        pik: bytes, 
        ppik: Optional[bytes] = None, 
        challenge: Optional[bytes] = None, 
        signature: Optional[bytes] = None
    ):
        self._uid = uid
        self._pik = pik
        self._ppik = ppik
        self._challenge = challenge
        self._signature = signature

    # --- Propiedades de Solo Lectura (Garantía de Inmutabilidad del Estado) ---

    @property
    def uid(self) -> str:
        return self._uid

    @property
    def pik(self) -> bytes:
        return self._pik

    @property
    def ppik(self) -> Optional[bytes]:
        return self._ppik

    @property
    def algorithm(self) -> str:
        return "Ed25519"

    @property
    def challenge(self) -> Optional[bytes]:
        return self._challenge

    @property
    def signature(self) -> Optional[bytes]:
        return self._signature

    @property
    def has_private_key(self) -> bool:
        return self._ppik is not None

    @property
    def is_local(self) -> bool:
        return self.has_private_key

    @property
    def is_remote(self) -> bool:
        return not self.is_local

    @property
    def pik_fingerprint(self) -> str:
        return hashlib.sha256(self._pik).hexdigest()

    @property
    def ppik_fingerprint(self) -> str:
        if self.is_remote: return None
        else:
            return hashlib.sha256(self._ppik).hexdigest()

    @property
    def uid_fingerprint(self) -> str:
        return hashlib.sha256(self._uid.encode("utf-8")).hexdigest()

    # --- Métodos de Operación Criptográfica ---

    @classmethod
    def create(cls) -> "EntityIdentity":
        """Genera una nueva identidad local con un par de claves único."""
        # Requiere Python 3.12+ para uuid.uuid7()
        uid_str = str(uuid7())
        
        # Generación de par de claves bajo la curva Ed25519
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        ppik_bytes = private_key.private_bytes_raw()
        pik_bytes = public_key.public_bytes_raw()
        
        instance = cls(uid=uid_str, pik=pik_bytes, ppik=ppik_bytes)
        instance._regenerate_challenge()
        return instance

    def _regenerate_challenge(self) -> None:
        """Construye un nuevo desafío criptográfico y lo firma."""
        if not self._ppik:
            raise PermissionError("Instancia remota/read-only: No se dispone de ppik para firmar retos.")
        
        # Estructura binaria del reto: [Timestamp (8 bytes Big-Endian)] + [Nonce (16 bytes)]
        timestamp = int(time.time())
        nonce = os.urandom(16)
        self._challenge = struct.pack(">Q", timestamp) + nonce
        
        # Firma del desafío con la clave privada local
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(self._ppik)
        self._signature = private_key.sign(self._challenge)

    def validate(self) -> bool:
        """Verifica la validez temporal y la firma del desafío actual."""
        if not self._challenge or not self._signature:
            return False
        
        try:
            # 1. Extracción y validación del timestamp (Anti-Replay)
            if len(self._challenge) < 8:
                return False
            timestamp = struct.unpack(">Q", self._challenge[:8])[0]
            current_time = int(time.time())
            
            if (current_time - timestamp) > self.CHALLENGE_TTL_SECONDS or timestamp > current_time:
                return False  # El desafío ha expirado o pertenece al futuro (desincronización de reloj)
            
            # 2. Verificación matemática de la firma Ed25519
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(self._pik)
            public_key.verify(self._signature, self._challenge)
            return True
            
        except (InvalidSignature, struct.error, ValueError):
            return False

    def sign(self, data: bytes) -> bytes:
        """Firma datos arbitrarios utilizando la clave privada (ppik)."""
        if not self._ppik:
            raise PermissionError("Instancia remota/read-only: Operación de firma no disponible.")
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(self._ppik)
        return private_key.sign(data)

    @staticmethod
    def verify_sign(data: bytes, pik: bytes, signature: bytes) -> bool:
        """Verifica una firma Ed25519 externa sobre un contenido específico."""
        try:
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(pik)
            public_key.verify(signature, data)
            return True
        except (InvalidSignature, ValueError):
            return False

    # --- Serialización y Deserialización (Estructuración de Datos) ---

    def to_dict(self, include_private: bool = False) -> Dict[str, Any]:
        """Exporta la identidad. Regenera el reto si es la identidad local."""
        if self._ppik:
            self._regenerate_challenge()
            
        exported = {
            "uid": self._uid,
            "pik": base64.b64encode(self._pik).decode("utf-8"),
            "challenge": base64.b64encode(self._challenge).decode("utf-8") if self._challenge else None,
            "signature": base64.b64encode(self._signature).decode("utf-8") if self._signature else None,
            "algorithm": self.algorithm
        }
        
        if include_private and self._ppik:
            exported["ppik"] = base64.b64encode(self._ppik).decode("utf-8")
            
        return exported

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EntityIdentity":
        """Rehidrata una instancia a partir de un diccionario con datos en Base64."""
        ppik_bytes = base64.b64decode(data["ppik"].encode("utf-8")) if "ppik" in data else None
        challenge_bytes = base64.b64decode(data["challenge"].encode("utf-8")) if data.get("challenge") else None
        signature_bytes = base64.b64decode(data["signature"].encode("utf-8")) if data.get("signature") else None
        
        return cls(
            uid=data["uid"],
            pik=base64.b64decode(data["pik"].encode("utf-8")),
            ppik=ppik_bytes,
            challenge=challenge_bytes,
            signature=signature_bytes
        )

    def to_json(self, include_private: bool = False) -> str:
        """Serializa de forma segura la estructura interna a formato JSON string."""
        return json.dumps(self.to_dict(include_private=include_private))

    @classmethod
    def from_json(cls, data: str) -> "EntityIdentity":
        """Rehidrata la instancia directamente desde un JSON string."""
        return cls.from_dict(json.loads(data))