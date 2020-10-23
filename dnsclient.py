import socket
import dnsutils

SEPARATOR = '-' * 64

class DNSClient:
    def __init__(self, root, domain):
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.root = root
        self.domainQuery = dnsutils.getQueryMessage(domain)
        self.resolved = False

    def resolve(self):
        while (not self.resolved):
            self.udp.connect((self.root, 53))
            self.udp.sendall(self.domainQuery)
            data = self.udp.recv(dnsutils.MAX_MESSAGE_SIZE)
            dnsMessage = dnsutils.parseDNSResponse(data)
            print(SEPARATOR)
            print('DNS server to query:', self.root)
            print(dnsMessage)
            if (len(dnsMessage.answers) > 0):
                break
            self.root = dnsMessage.additional.pop().rdata
        self.udp.close()
