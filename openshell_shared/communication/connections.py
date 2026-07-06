from typing import Dict
from typing import List

from .transport.base import TransportInterface


class ConnectionRegistry:

    def __init__(self):

        self._connections: Dict[
            str,
            TransportInterface
        ] = {}

    # =====================================================
    # REGISTRO
    # =====================================================

    def regist_connection(
        self,
        connection_uid: str,
        transport: TransportInterface
    ) -> bool:

        print("[CONNECTION-REGISTRY] Registered connection:", connection_uid)
        print("[CONNECTION-REGISTRY] Transport:")
        print(transport)

        self._connections[
            connection_uid
        ] = transport

        return True

    def unregist_connection(
        self,
        connection_uid: str,
        transport: TransportInterface
    ) -> bool:

        if connection_uid not in self._connections:
            return False

        del self._connections[
            connection_uid
        ]

        return True

    # =====================================================
    # CONSULTAS
    # =====================================================

    def resolve_transport(
        self,
        connection_uid: str
    ) -> TransportInterface | None:

        print("[CONNECTION-REGISTRY] Resolviendo transporte:", connection_uid)
        print(self._connections.get(connection_uid))

        return self._connections.get(
            connection_uid
        )

    def query_connections(
        self
    ) -> List[str]:

        return list(
            self._connections.keys()
        )

    def exists(
        self,
        connection_uid: str
    ) -> bool:

        return (
            connection_uid
            in self._connections
        )

    def count(
        self
    ) -> int:

        return len(
            self._connections
        )