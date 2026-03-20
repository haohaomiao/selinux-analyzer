# Handlers module - syscall 分析逻辑层

from .socket_handler import handle_socket
from .connect_handler import handle_connect
from .dup2_handler import handle_dup2

__all__ = [
    "handle_socket",
    "handle_connect",
    "handle_dup2",
]
