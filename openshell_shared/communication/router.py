# Library import
import queue

# Classes definition
class Router:
    def __init__(self,
        connection_registry,
        tunnel_registry,
        flow_manager,

        tx_queue: queue.Queue,
        rx_queue: queue.Queue
    ):
        self._connection_registry = connection_registry
        self._tunnel_registry = tunnel_registry
        self._flow = flow_manager
        
        self.rx_queue = rx_queue
        self.tx_queue = tx_queue

        self._active: bool = False


    async def handle_packet(self, connection_uid: str, packet: dict) -> bool:
        print(f"[ROUTER] Handling packet:")
        print(packet)

        rx_queue.put(packet)

        return True

    async def _tx_dispatcher(self):
        while self._active:
            # Get datapackage
            packet = self.tx_queue.get()

            # Resolve EntityUID -> ConnectionUID -> Send datapackage
            pass

    async def start(self) -> bool:
        self._active = True

        return True

    async def stop(self) -> bool:
        self._active = False

        return True