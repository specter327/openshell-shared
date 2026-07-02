from enum import Enum

SCHEMA_VERSION = 1

class CertificateType(str, Enum):
    DOMAIN_MANAGEMENT = "DOMAIN_MANAGEMENT"
    MANAGER_AUTHORIZATION = "MANAGER_AUTHORIZATION"

    @staticmethod
    def exists(value: str) -> bool:
        return value in CertificateType._value2member_map_