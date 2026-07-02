# shell/protocol.py

# =====================================================
# LIBRARY IMPORTS
# =====================================================

import time

from uuid6 import uuid7

from .models import (
    ProtocolType,
    ProtocolStandard
)


# =====================================================
# PACKAGE BASE
# =====================================================

class PackageBase:

    def __init__(
        self,
        auth_token: str,
        tunnel_token: str,
        session_token: str
    ):

        self.auth_token = auth_token
        self.tunnel_token = tunnel_token
        self.session_token = session_token

    def header(self) -> dict:

        return {
            "auth_token":
                self.auth_token,

            "tunnel_token":
                self.tunnel_token,

            "session_token":
                self.session_token,

            "packet_type":
                "DATA"
        }


# =====================================================
# SHELL PROTOCOL
# =====================================================

class ShellProtocol(
    PackageBase
):

    PROTOCOL = (
        ProtocolStandard.SHELL
    )

    PROTOCOL_VERSION = 2

    # ================================================
    # INTERNAL
    # ================================================

    def _payload(
        self,
        protocol_type: str,
        event: str,
        **kwargs
    ):

        payload = {
            "protocol":
                self.PROTOCOL.value,

            "protocol_type":
                protocol_type,

            "protocol_version":
                self.PROTOCOL_VERSION,

            "event":
                event,

            "timestamp":
                time.time()
        }

        payload.update(kwargs)

        return payload

    # ================================================
    # CLIENT EVENTS
    # ================================================

    def open(self):

        packet = self.header()

        packet["payload"] = (
            self._payload(
                protocol_type=
                    ProtocolType.CLIENT.value,

                event="OPEN",

                request_id=
                    str(uuid7())
            )
        )

        return packet

    def input(
        self,
        data: str
    ):

        packet = self.header()

        packet["payload"] = (
            self._payload(
                protocol_type=
                    ProtocolType.CLIENT.value,

                event="INPUT",

                data=data
            )
        )

        return packet

    def resize(
        self,
        rows: int,
        cols: int
    ):

        packet = self.header()

        packet["payload"] = (
            self._payload(
                protocol_type=
                    ProtocolType.CLIENT.value,

                event="RESIZE",

                rows=rows,
                cols=cols
            )
        )

        return packet

    def signal(
        self,
        signal_name: str
    ):

        packet = self.header()

        packet["payload"] = (
            self._payload(
                protocol_type=
                    ProtocolType.CLIENT.value,

                event="SIGNAL",

                signal=signal_name
            )
        )

        return packet

    def close(self):

        packet = self.header()

        packet["payload"] = (
            self._payload(
                protocol_type=
                    ProtocolType.CLIENT.value,

                event="CLOSE"
            )
        )

        return packet

    # ================================================
    # SERVER EVENTS
    # ================================================

    def output(
        self,
        session_token: str,
        data: str
    ):

        packet = self.header()

        packet["session_token"] = (
            session_token
        )

        packet["payload"] = (
            self._payload(
                protocol_type=
                    ProtocolType.SERVER.value,

                event="OUTPUT",

                data=data
            )
        )

        return packet

    def exit(
        self,
        session_token: str,
        return_code: int
    ):

        packet = self.header()

        packet["session_token"] = (
            session_token
        )

        packet["payload"] = (
            self._payload(
                protocol_type=
                    ProtocolType.SERVER.value,

                event="EXIT",

                return_code=
                    return_code
            )
        )

        return packet