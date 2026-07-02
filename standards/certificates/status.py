from enum import Enum


class CertificateStatus(str, Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    COMPROMISED = "COMPROMISED"

    @staticmethod
    def exists(value: str) -> bool:
        return value in CertificateStatus._value2member_map_