import asyncio
import websockets

from asyncdatapackage import AsyncDataPackage


class WSStreamClient:
    """
    Convierte WebSocket en stream tipo TCP para AsyncDataPackage.
    """

    def __init__(self, host: str, port: int):

        self._host = host
        self._port = port

        self._ws = None

        self._buffer = bytearray()
        self._recv_queue = asyncio.Queue()

        self._reader_task = None
        self._running = False

    # =====================================================
    # CONNECT
    # =====================================================

    async def connect(self):

        uri = f"ws://{self._host}:{self._port}"

        self._ws = await websockets.connect(
            uri,
            max_size=None,
            ping_interval=None
        )

        self._running = True

        self._reader_task = asyncio.create_task(
            self._reader_loop()
        )

    # =====================================================
    # READER LOOP (WS → STREAM BUFFER)
    # =====================================================

    async def _reader_loop(self):

        try:
            async for message in self._ws:

                if isinstance(message, str):
                    message = message.encode("utf-8")

                self._buffer.extend(message)

        except Exception:
            self._running = False

    # =====================================================
    # WRITE (STREAM → WS)
    # =====================================================

    async def write(self, data: bytes) -> bool:

        if not self._ws:
            return False

        try:
            await self._ws.send(data)
            return True
        except Exception:
            return False

    # =====================================================
    # READ (TCP-LIKE SEMANTICS)
    # =====================================================

    # =====================================================
    # READ (TCP-LIKE SEMANTICS FIXED)
    # =====================================================

    async def read(self, amount: int) -> bytes:

        # Bloquear solo si no hay absolutamente nada que leer
        while len(self._buffer) == 0:
            if not self._running:
                return b""
            await asyncio.sleep(0.001)

        # Extraer hasta 'amount' bytes, o la longitud actual (lo que sea menor)
        chunk_size = min(amount, len(self._buffer))
        
        result = bytes(self._buffer[:chunk_size])
        del self._buffer[:chunk_size]

        return result

    # =====================================================
    # CLOSE
    # =====================================================

    async def close(self):

        self._running = False

        if self._ws:
            await self._ws.close()

        if self._reader_task:
            self._reader_task.cancel()

            try:
                await self._reader_task
            except:
                pass


# =========================================================
# COMMUNICATION HANDLER (DROP-IN COMPATIBLE)
# =========================================================

class CommunicationHandler:

    def __init__(
        self,
        auth_token: str,
        tunnel_token: str,
        tunnel_port: int,
        tunnel_host: str = "127.0.0.1"
    ):
        self.auth_token = auth_token
        self.tunnel_token = tunnel_token

        self.tunnel_host = tunnel_host
        self.tunnel_port = tunnel_port

        self._stream = None
        self.datapackage = None

    # =====================================================
    # CONNECTION
    # =====================================================

    async def connect(self):

        self._stream = WSStreamClient(
            self.tunnel_host,
            self.tunnel_port
        )

        await self._stream.connect()

        async def write_fn(data: bytes):
            return await self._stream.write(data)

        async def read_fn():
            # IMPORTANT: AsyncDataPackage expects chunk reads
            return await self._stream.read(65536)

        self.datapackage = AsyncDataPackage(
            write_function=write_fn,
            read_function=read_fn,
            backpressure_mode="drop_oldest"
        )

        await self.datapackage.start()

        await self._bind()

    # =====================================================
    # BIND
    # =====================================================

    async def _bind(self):

        await self.datapackage.send_datapackage({
            "auth_token": self.auth_token,
            "tunnel_token": self.tunnel_token,
            "packet_type": "CONTROL",
            "packet_control": "BIND"
        })

    # =====================================================
    # SEND
    # =====================================================

    async def send_datapackage(self, packet: dict):

        await self.datapackage.send_datapackage(packet)

    # =====================================================
    # RECEIVE
    # =====================================================

    async def receive_datapackage(self):

        return await self.datapackage.receive_datapackage()

    # =====================================================
    # CLOSE
    # =====================================================

    async def close(self):

        if self.datapackage:
            await self.datapackage.stop()

        if self._stream:
            await self._stream.close()