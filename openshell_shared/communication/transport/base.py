from abc import ABC, abstractmethod
from typing import Dict
from typing import List
from typing import Callable
from typing import Awaitable

from .models import CONNECTION_STATUS


class TransportInterface(ABC):

    def __init__(self):

        self._connections: Dict[
            str,
            object
        ] = {}

        self._on_connection: List[
            Callable[
                [str, object],
                Awaitable[None]
            ]
        ] = []

        self._on_disconnection: List[
            Callable[
                [str, object],
                Awaitable[None]
            ]
        ] = []

        self._on_error: List[
            Callable[
                [Exception, object],
                Awaitable[None]
            ]
        ] = []

    # =====================================================
    # EVENTOS
    # =====================================================

    async def _emit_connection(
        self,
        connection_uid: str,
        transport: object
    ):

        for callback in self._on_connection:

            try:
                await callback(
                    connection_uid,
                    transport
                )

            except Exception:
                pass

    async def _emit_disconnection(
        self,
        connection_uid: str,
        transport: object
    ):

        for callback in self._on_disconnection:

            try:
                await callback(
                    connection_uid,
                    transport
                )

            except Exception:
                pass

    async def _emit_error(
        self,
        error: Exception,
        transport: object
    ):

        for callback in self._on_error:

            try:
                await callback(
                    error,
                    transport
                )

            except Exception:
                pass

    # =====================================================
    # CICLO DE VIDA
    # =====================================================

    @abstractmethod
    async def start(
        self
    ) -> bool:
        """
        Inicializa el transporte.
        Reserva recursos internos.
        No necesariamente comienza a escuchar conexiones.
        """
        pass

    @abstractmethod
    async def stop(
        self
    ) -> bool:
        """
        Detiene completamente el transporte.
        """
        pass

    # =====================================================
    # LISTENER
    # =====================================================

    @abstractmethod
    async def listen(
        self,
        host: str,
        port: int
    ) -> bool:
        """
        Comienza a aceptar conexiones entrantes.
        """
        pass

    @abstractmethod
    async def stop_listener(
        self
    ) -> bool:
        """
        Detiene únicamente el listener.
        Las conexiones existentes permanecen activas.
        """
        pass

    # =====================================================
    # CONEXIONES
    # =====================================================

    @abstractmethod
    async def connect(
        self,
        host: str,
        port: int
    ) -> str | None:
        """
        Establece una conexión saliente.
        """
        pass

    @abstractmethod
    async def close_connection(
        self,
        connection_uid: str
    ) -> bool:
        pass

    # =====================================================
    # STREAM
    # =====================================================

    @abstractmethod
    async def send(
        self,
        connection_uid: str,
        data: bytes
    ) -> bool:
        pass

    @abstractmethod
    async def receive(
        self,
        connection_uid: str,
        amount: int
    ) -> bytes:
        pass

    # =====================================================
    # CONSULTAS
    # =====================================================

    @abstractmethod
    def query_connections(
        self
    ) -> List[str]:
        pass

    @abstractmethod
    def query_connection_status(
        self,
        connection_uid: str
    ) -> CONNECTION_STATUS:
        pass

    @abstractmethod
    def query_connection_information(
        self,
        connection_uid: str
    ) -> dict:
        pass

    @abstractmethod
    def is_listening(
        self
    ) -> bool:
        pass

    # =====================================================
    # SUBSCRIPCIONES
    # =====================================================

    def on_connection_subscribe(
        self,
        callback
    ):

        if callback not in self._on_connection:
            self._on_connection.append(callback)

    def on_disconnection_subscribe(
        self,
        callback
    ):

        if callback not in self._on_disconnection:
            self._on_disconnection.append(callback)

    def on_error_subscribe(
        self,
        callback
    ):

        if callback not in self._on_error:
            self._on_error.append(callback)

    def on_connection_unsubscribe(
        self,
        callback
    ):

        if callback in self._on_connection:
            self._on_connection.remove(callback)

    def on_disconnection_unsubscribe(
        self,
        callback
    ):

        if callback in self._on_disconnection:
            self._on_disconnection.remove(callback)

    def on_error_unsubscribe(
        self,
        callback
    ):

        if callback in self._on_error:
            self._on_error.remove(callback)