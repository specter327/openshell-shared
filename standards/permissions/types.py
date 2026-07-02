from enum import Enum


class Permission(str, Enum):

    DOMAIN_READ = "domain.read"

    DOMAIN_WRITE = "domain.write"

    ENTITY_REGISTER = "entity.register"

    ENTITY_REVOKE = "entity.revoke"

    PROXY_USE = "proxy.use"