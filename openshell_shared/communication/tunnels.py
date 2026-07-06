from typing import Dict
from typing import List
from typing import Set

from .transport.base import TransportInterface


class TunnelRegistry:

    def __init__(self):

        # EntityUID -> Set[ConnectionUID]
        self._tunnels: Dict[
            str,
            Set[str]
        ] = {}

        # ConnectionUID -> EntityUID
        self._connections: Dict[
            str,
            str
        ] = {}

    # =====================================================
    # REGISTRO
    # =====================================================

    def attach_tunnel(
        self,
        entity_uid: str,
        connection_uid: str
    ) -> bool:

        if entity_uid not in self._tunnels:

            self._tunnels[
                entity_uid
            ] = set()

        self._tunnels[
            entity_uid
        ].add(
            connection_uid
        )

        self._connections[
            connection_uid
        ] = entity_uid

        return True

    def deattach_tunnel(
        self,
        entity_uid: str,
        connection_uid
    ) -> bool:

        # =================================================
        # ADAPTADOR
        # =================================================
        #
        # Permite:
        #
        # deattach_tunnel(
        #     entity_uid,
        #     connection_uid
        # )
        #
        # o:
        #
        # deattach_tunnel(
        #     connection_uid,
        #     transport
        # )
        #
        # =================================================

        if isinstance(
            connection_uid,
            TransportInterface
        ):

            print(
                f"[TUNNEL-REGISTRY] "
                f"Automatic disconnect detected"
            )

            transport = connection_uid

            connection_uid = entity_uid

            entity_uid = (
                self._connections.get(
                    connection_uid
                )
            )

            if entity_uid is None:

                print(
                    f"[TUNNEL-REGISTRY] "
                    f"Connection not registered: "
                    f"{connection_uid}"
                )

                return False

        # =================================================
        # VALIDACIONES
        # =================================================

        if entity_uid not in self._tunnels:
            return False

        # =================================================
        # ELIMINAR RELACION
        # =================================================

        self._tunnels[
            entity_uid
        ].discard(
            connection_uid
        )

        self._connections.pop(
            connection_uid,
            None
        )

        # =================================================
        # LIMPIEZA
        # =================================================

        if not self._tunnels[
            entity_uid
        ]:

            del self._tunnels[
                entity_uid
            ]

        return True

    # =====================================================
    # RESOLUCIONES
    # =====================================================

    def resolve_entity(
        self,
        entity_uid: str
    ) -> List[str]:

        return list(
            self._tunnels.get(
                entity_uid,
                set()
            )
        )

    def resolve_connection(
        self,
        connection_uid: str
    ) -> str | None:

        return self._connections.get(
            connection_uid
        )

    # =====================================================
    # CONSULTAS
    # =====================================================

    def query_entities(
        self
    ) -> List[str]:

        return list(
            self._tunnels.keys()
        )

    def query_connections(
        self,
        entity_uid: str
    ) -> List[str]:

        return self.resolve_entity(
            entity_uid
        )

    def query_registered_connections(
        self
    ) -> List[str]:

        return list(
            self._connections.keys()
        )

    def exists(
        self,
        entity_uid: str
    ) -> bool:

        return (
            entity_uid
            in self._tunnels
        )

    def exists_connection(
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
            self._tunnels
        )

    def count_connections(
        self
    ) -> int:

        return len(
            self._connections
        )