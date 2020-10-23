import socket
import dnsutils

SEPARATOR_COUNT = 64

class DNSClient:
    def __init__(self, root, domain):
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.root = root
        self.domain = domain
        self.resolved = False

    def resolve(self):
        self.udp.connect((self.root, 53))
        self.udp.sendall(dnsutils.getQueryMessage(self.domain))
        data = self.udp.recv(8192)
        self.udp.close()
        print('-' * SEPARATOR_COUNT)
        print('DNS server to query:', self.root)
        print(dnsutils.parseDNSResponse(data))
