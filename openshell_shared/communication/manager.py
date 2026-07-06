# Library import
from .connections import ConnectionRegistry
from .tunnels import TunnelRegistry
from .flow import FlowManager
from .transport.ws import WSTransport
from .router import Router
from .models import RoleType
import random
import queue

# Classes definition
class CommunicationManager:
	def __init__(self,
		mode=RoleType
	):
		self._connection_registry = ConnectionRegistry()
		self._tunnel_registry = TunnelRegistry()
		self._flow = FlowManager(
			connection_registry=self._connection_registry
		)
		self.tx_queue = queue.Queue()
		self.rx_queue = queue.Queue()
		self.mode = mode
		self._router = Router(
			connection_registry=self._connection_registry,
			tunnel_registry=self._tunnel_registry,
			flow_manager=self._flow,

			tx_queue=self.tx_queue,
			rx_queue=self.rx_queue
		)
		self._ws = WSTransport()

	async def start(self) -> bool:
		# Connection subscription
		## Transport
		self._ws.on_connection_subscribe(
			self._connection_registry.regist_connection
		)

		self._ws.on_disconnection_subscribe(
			self._connection_registry.unregist_connection
		)

		## Flow Manager
		self._ws.on_connection_subscribe(
			self._flow.attach_connection
		)

		self._ws.on_disconnection_subscribe(
			self._flow.detach_connection
		)

		## Tunnels
		self._ws.on_disconnection_subscribe(
			self._tunnel_registry.deattach_tunnel
		)

		# Router
		self._flow.on_datapackage_receive(
			self._router.handle_packet
		)

		## Start
		await self._router.start()

		# Transport
		## Start
		await self._ws.start()

		if self.mode == RoleType.SERVER.value or self.mode == RoleType.CLIENT_SERVER:
			await self._ws.listen(
				host="0.0.0.0",
				port=40000
			)

		return True

	async def stop(self) -> bool:
		# Router
		## Stop
		await self._router.stop()
		
		# Transport
		## Stop
		await self._ws.stop()

		return True