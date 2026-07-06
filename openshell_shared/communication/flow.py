"""
FlowManager

Owns AsyncDataPackage instances for active
connections and provides high-level packet I/O.

Responsibilities:

- Attach connections
- Detach connections
- Send datapackages
- Receive datapackage events
- Manage AsyncDataPackage lifecycle

Author:
    Specter327

License:
    MIT
"""

from __future__ import annotations

import asyncio
import logging

from typing import (
    Callable,
    Optional
)

from asyncdatapackage import AsyncDataPackage

logger = logging.getLogger(__name__)


class FlowManager:

    def __init__(
        self,
        connection_registry
    ):
        self._connection_registry = (
            connection_registry
        )

        self._attached_connections = {}

        self._datapackage_callbacks = []

    # =====================================================
    # ATTACH / DETACH
    # =====================================================

    async def attach_connection(
        self,
        connection_uid: str,
        transport: object
    ) -> bool:

        print("[FLOW-MANAGER] Apropiando conexion:", connection_uid)
        print("[FLOW-MANAGER] Transport:")
        print(transport)

        if connection_uid in (
            self._attached_connections
        ):
            return True

        connection = (
            self._connection_registry
            .resolve_transport(
                connection_uid
            )
        )

        if connection is None:

            logger.warning(
                f"Connection not found: "
                f"{connection_uid}"
            )

            return False

        print("[FLOW-MANAGER] Connection resolved:")
        print(connection)

        datapackage = (
            AsyncDataPackage(
                write_function=(
                    connection.send
                ),
                read_function=(
                    connection.receive
                ),

                write_arguments=(connection_uid,),
                read_arguments=(connection_uid, 4096),

                backpressure_mode="drop_oldest"
            )
        )

        datapackage.on_datapackage_receive(
            lambda packet,
            uid=connection_uid:
            asyncio.create_task(
                self._on_datapackage(
                    uid,
                    packet
                )
            )
        )

        print("A")

        await datapackage.start()

        self._attached_connections[
            connection_uid
        ] = datapackage

        print("[FLOW-MANAGER] Conexion apropiada exitosamente:", connection_uid)

        logger.info(
            f"Connection attached: "
            f"{connection_uid}"
        )

        return True

    async def detach_connection(
        self,
        connection_uid: str,
        transport: object
    ) -> bool:

        datapackage = (
            self._attached_connections.pop(
                connection_uid,
                None
            )
        )

        if datapackage is None:
            return False

        await datapackage.stop()

        logger.info(
            f"Connection detached: "
            f"{connection_uid}"
        )

        return True

    # =====================================================
    # DATAPACKAGES
    # =====================================================

    async def send_datapackage(
        self,
        connection_uid: str,
        datapackage: dict
    ) -> bool:

        print(f"[FLOW-MANAGER] Sending datapackage to: {connection_uid}...")
        print(f"[FLOW-MANAGER] Datapackage:")
        print(datapackage)

        controller = (
            self._attached_connections.get(
                connection_uid
            )
        )

        print(f"[FLOW-MANAGER] Connection UID: {connection_uid} | Controller: {controller}")

        if controller is None:

            logger.warning(
                f"Connection not attached: "
                f"{connection_uid}"
            )

            return False

        return await (
            controller.send_datapackage(
                datapackage
            )
        )

    def get_datapackage_controller(
        self,
        connection_uid: str
    ) -> Optional[
        AsyncDataPackage
    ]:

        return (
            self._attached_connections.get(
                connection_uid
            )
        )

    # =====================================================
    # EVENTS
    # =====================================================

    async def _on_datapackage(
        self,
        connection_uid: str,
        packet: dict
    ):

        print("Paquete de datos recibido:")
        print(packet)

        callbacks = tuple(
            self._datapackage_callbacks
        )

        for callback in callbacks:

            try:

                if asyncio.iscoroutinefunction(
                    callback
                ):

                    asyncio.create_task(
                        callback(
                            connection_uid,
                            packet
                        )
                    )

                else:

                    callback(
                        connection_uid,
                        packet
                    )

            except Exception:

                logger.exception(
                    "FlowManager callback failed"
                )

    def on_datapackage_receive(
        self,
        callback: Callable
    ) -> bool:

        if not callable(
            callback
        ):
            raise TypeError(
                "callback must be callable"
            )

        if callback not in (
            self._datapackage_callbacks
        ):

            self._datapackage_callbacks.append(
                callback
            )

        return True

    def remove_datapackage_callback(
        self,
        callback: Callable
    ) -> bool:

        try:

            self._datapackage_callbacks.remove(
                callback
            )

            return True

        except ValueError:

            return False

    # =====================================================
    # QUERIES
    # =====================================================

    def query_attached_connections(
        self
    ) -> list[str]:

        return list(
            self._attached_connections.keys()
        )

    def is_attached(
        self,
        connection_uid: str
    ) -> bool:

        return (
            connection_uid
            in self._attached_connections
        )

    def attached_count(
        self
    ) -> int:

        return len(
            self._attached_connections
        )

    # =====================================================
    # REGISTRY SUBSCRIPTIONS
    # =====================================================

    async def on_connection(
        self,
        connection_uid: str
    ):

        await self.attach_connection(
            connection_uid
        )

    async def on_disconnection(
        self,
        connection_uid: str
    ):

        await self.detach_connection(
            connection_uid
        )