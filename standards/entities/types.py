from enum import Enum


class EntityType(str, Enum):

    AGENT = "AGENT"

    CONSOLE = "CONSOLE"

    PROXY = "PROXY"

    MANAGER = "MANAGER"

    ROOT_AUTHORITY = "ROOT_AUTHORITY"