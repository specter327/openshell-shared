from enum import Enum


class TransportType(str, Enum):
    TCP = "TCP"
    UDP = "UDP"

    HTTP = "HTTP"
    HTTPS = "HTTPS"

    WEBSOCKET = "WEBSOCKET"
    WEBSOCKET_SECURE = "WEBSOCKET_SECURE"

    QUIC = "QUIC"

    BLUETOOTH = "BLUETOOTH"
    SERIAL = "SERIAL"

    TOR = "TOR"


    @staticmethod
    def exists(value: str) -> bool:
        return value in TransportType._value2member_map_