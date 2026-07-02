# Library import
from enum import Enum

# Classes
class Permission(Enum):
	# Agents
	AGENT_READ = "agent.read"
	AGENT_EXECUTE = "agent.execute"

	# Proxys
	PROXY_USE = "proxy.use"

	# Domains
	DOMAIN_ADMIN = "domain.admin"