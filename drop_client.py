import socket
from drop_config import DropConfig

# magic_string = 'SECUREDROP'

class SecureDropClient:
    def __init__(self, config):
        self.config = config
        pass

    def ping(self, email):
        