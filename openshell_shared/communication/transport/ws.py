# ws.py

import asyncio
import time
import binascii
import os

from typing import Optional, List, Dict, Any

import websockets
from websockets.server import WebSocketServer

from .base import TransportInterface
from .models import CONNECTION_STATUS


# =====================================================
# UUID v7 simple (igual que TCP transport)
# =====================================================

def generate_uuid7() -> str:
    timestamp_ms = int(time.time() * 1000)
    random_bytes = bytearray(os.urandom(16))

    random_bytes[0] = (timestamp_ms >> 40) & 0xFF
    random_bytes[1] = (timestamp_ms >> 32) & 0xFF
    random_bytes[2] = (timestamp_ms >> 24) & 0xFF
    random_bytes[3] = (timestamp_ms >> 16) & 0xFF
    random_bytes[4] = (timestamp_ms >> 8) & 0xFF
    random_bytes[5] = (timestamp_ms) & 0xFF

    random_bytes[6] = (random_bytes[6] & 0x0F) | 0x70
    random_bytes[8] = (random_bytes[8] & 0x3F) | 0x80

    hex_value = binascii.hexlify(random_bytes).decode()

    return (
        f"{hex_value[:8]}-"
        f"{hex_value[8:12]}-"
        f"{hex_value[12:16]}-"
        f"{hex_value[16:20]}-"
        f"{hex_value[20:]}"
    )


# =====================================================
# WebSocket Transport
# =====================================================

class WSTransport(TransportInterface):

    def __init__(self):
        """
        Inicializa las estructuras de datos internas del transporte.
        Se remueven 'host' y 'port' del constructor para cumplir con el contrato.
        """
        super().__init__()

        self._server: Optional[WebSocketServer] = None
        self._running: bool = False

        # Buffers de recepción por conexión (simula stream TCP)
        self._rx_buffers: Dict[str, bytearray] = {}

        # Locks de escritura concurrentes por conexión
        self._send_locks: Dict[str, asyncio.Lock] = {}

        # Mapping uid -> websocket object (Client o Server)
        self._ws_map: Dict[str, Any] = {}

    # =====================================================
    # CICLO DE VIDA
    # =====================================================

    async def start(self) -> bool:
        if self._running:
            return True
        
        self._running = True
        return True

    async def stop(self) -> bool:
        if not self._running:
            return True

        # 1. Detener el listener de manera segura sin tirar conexiones de inmediato
        await self.stop_listener()

        # 2. Modificar estado global
        self._running = False

        # 3. Forzar el cierre de todas las conexiones activas remanentes
        active_connections = list(self._connections.keys())
        for uid in active_connections:
            await self.close_connection(uid)

        return True

    # =====================================================
    # LISTENER
    # =====================================================

    async def listen(self, host: str, port: int) -> bool:
        if not self._running:
            return False
        
        if self._server:
            return True  # Ya se encuentra escuchando

        try:
            self._server = await websockets.serve(
                self._handle_client,
                host,
                port,
                max_size=None,
            )
            return True
        except Exception as e:
            await self._emit_error(e, self)
            return False

    async def stop_listener(self) -> bool:
        if not self._server:
            return True

        try:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            return True
        except Exception as e:
            await self._emit_error(e, self)
            return False

    # =====================================================
    # CONEXIONES (CLIENT MODE)
    # =====================================================

    async def connect(self, host: str, port: int) -> str | None:
        if not self._running:
            return None

        try:
            websocket = await websockets.connect(
                f"ws://{host}:{port}",
                max_size=None
            )

            connection_uid = generate_uuid7()

            self._connections[connection_uid] = {
                "status": CONNECTION_STATUS.OPEN,
                "peername": (host, port)
            }

            self._ws_map[connection_uid] = websocket
            self._rx_buffers[connection_uid] = bytearray()
            self._send_locks[connection_uid] = asyncio.Lock()

            # Bucle de lectura asíncrono para el cliente dedicado
            asyncio.create_task(
                self._client_receive_loop(connection_uid, websocket)
            )

            await self._emit_connection(connection_uid, self)
            return connection_uid

        except Exception as e:
            await self._emit_error(e, self)
            return None

    async def close_connection(self, connection_uid: str) -> bool:
        conn = self._connections.get(connection_uid)
        if not conn:
            return False

        if conn["status"] == CONNECTION_STATUS.CLOSED:
            return True

        conn["status"] = CONNECTION_STATUS.CLOSED
        ws = self._ws_map.pop(connection_uid, None)

        if ws:
            try:
                await ws.close()
            except Exception:
                pass

        self._rx_buffers.pop(connection_uid, None)
        self._send_locks.pop(connection_uid, None)

        await self._emit_disconnection(connection_uid, self)
        return True

    # =====================================================
    # STREAM
    # =====================================================

    async def send(self, connection_uid: str, data: bytes) -> bool:
        ws = self._ws_map.get(connection_uid)
        if not ws:
            return False

        conn = self._connections.get(connection_uid)
        if not conn or conn["status"] != CONNECTION_STATUS.OPEN:
            return False

        try:
            lock = self._send_locks.get(connection_uid)
            if not lock:
                lock = asyncio.Lock()
                self._send_locks[connection_uid] = lock

            async with lock:
                await ws.send(data)

            return True
        except Exception as e:
            await self._emit_error(e, self)
            await self.close_connection(connection_uid)
            return False

    async def receive(self, connection_uid: str, amount: int) -> bytes:
        buffer = self._rx_buffers.get(connection_uid)
        if buffer is None:
            return b""

        conn = self._connections.get(connection_uid)
        if not conn or conn["status"] != CONNECTION_STATUS.OPEN:
            # Si la conexión se cerró pero aún quedan bytes remanentes en el buffer, se permite drenarlos
            if len(buffer) == 0:
                return b""

        if len(buffer) == 0:
            return b""

        chunk = buffer[:amount]
        del buffer[:amount]
        return bytes(chunk)

    # =====================================================
    # CONSULTAS
    # =====================================================

    def query_connections(self) -> List[str]:
        return list(self._connections.keys())

    def query_connection_status(self, connection_uid: str) -> CONNECTION_STATUS:
        conn = self._connections.get(connection_uid)
        if not conn:
            return CONNECTION_STATUS.CLOSED
        return conn["status"]

    def query_connection_information(self, connection_uid: str) -> dict:
        conn = self._connections.get(connection_uid)
        if not conn:
            return {}

        return {
            "connection_uid": connection_uid,
            "peername": conn.get("peername"),
            "status": conn["status"],
            "type": "websocket"
        }

    def is_listening(self) -> bool:
        return self._server is not None and self._server.is_serving()

    # =====================================================
    # INTERNOS / LOOPS DE RECEPCIÓN
    # =====================================================

    async def _handle_client(self, websocket):
        """Manejador interno para conexiones entrantes (Modo Servidor)."""
        uid = generate_uuid7()
        peer = websocket.remote_address

        self._connections[uid] = {
            "status": CONNECTION_STATUS.OPEN,
            "peername": peer,
        }

        self._ws_map[uid] = websocket
        self._rx_buffers[uid] = bytearray()
        self._send_locks[uid] = asyncio.Lock()

        await self._emit_connection(uid, self)

        try:
            async for message in websocket:
                if isinstance(message, str):
                    message = message.encode("utf-8")
                
                if uid in self._rx_buffers:
                    self._rx_buffers[uid].extend(message)
        except Exception as e:
            await self._emit_error(e, self)
        finally:
            await self.close_connection(uid)

    async def _client_receive_loop(self, uid: str, websocket):
        """Manejador interno para mensajes entrantes desde sockets salientes (Modo Cliente)."""
        try:
            async for message in websocket:
                if isinstance(message, str):
                    message = message.encode("utf-8")
                
                if uid in self._rx_buffers:
                    self._rx_buffers[uid].extend(message)
        except Exception as e:
            await self._emit_error(e, self)
        finally:
            await self.close_connection(uid)