"""Client transport for QTL2."""
import socket
from src.utils.network import BaseNetwork


class ClientNetwork(BaseNetwork):
    def __init__(self, ip, port, logger, *, server_name=None, **kwargs):
        super().__init__(ip, port, logger, **kwargs)
        self.server_name = server_name or ip

    def connect(self):
        self.sock = socket.create_connection((self.ip, self.port), timeout=self.handshake_timeout)
