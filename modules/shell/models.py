# shell/models.py

# =====================================================
# LIBRARY IMPORTS
# =====================================================

from enum import Enum


# =====================================================
# PROTOCOL TYPE
# =====================================================

class ProtocolType(str, Enum):

    CLIENT = "CLIENT"
    SERVER = "SERVER"


# =====================================================
# PROTOCOL STANDARD
# =====================================================

class ProtocolStandard(str, Enum):

    SHELL = "SHELL"
    FTP = "FTP"
    SPECIAL = "SPECIAL"


# =====================================================
# SHELL EVENTS
# =====================================================

class ShellEvent(str, Enum):

    OPEN = "OPEN"

    INPUT = "INPUT"

    OUTPUT = "OUTPUT"

    RESIZE = "RESIZE"

    SIGNAL = "SIGNAL"

    CLOSE = "CLOSE"


# =====================================================
# SHELL SIGNALS
# =====================================================

class ShellSignal(str, Enum):

    SIGINT = "SIGINT"
    SIGTERM = "SIGTERM"
    SIGKILL = "SIGKILL"
    SIGHUP = "SIGHUP"
    SIGQUIT = "SIGQUIT"
    SIGTSTP = "SIGTSTP"