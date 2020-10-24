import socket
import dnsutils
import sys
from typing import Tuple

SEPARATOR = '-' * 64

class DNSClient:
    def __init__(self, domain, root):
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.settimeout(5)
        self.root = root
        self.domain = domain
        self.domainQuery = dnsutils.getQueryMessage(domain)
        self.resolved = False

    def resolve(self):
        try:
            visited = {}
            resolved = resolveHelper(self.root, self.domainQuery, self.udp, visited)
            if (not resolved):
                print(SEPARATOR)
                print(f'Failed to resolve \'{self.domain}\'. Please try another root DNS server.')
        except (socket.timeout):
            print(SEPARATOR)
            print('Socket timeout. Please try again.')
        finally:
            self.udp.close()

def resolveHelper(root, query, udp, visited) -> bool:
    if (root in visited):
        return False
    udp.connect((root, 53))
    udp.sendall(query)
    data = udp.recv(dnsutils.MAX_MESSAGE_SIZE)
    dnsMessage = dnsutils.parseDNSResponse(data)
    print(SEPARATOR)
    print('DNS server to query:', root)
    print(dnsMessage)
    if (len(dnsMessage.answers) > 0):
        return True
    for server in dnsMessage.additional:
        resolved = resolveHelper(server.rdata, query, udp, visited)
        if (resolved):
            return True
    visited[root] = True
    return False

def commandLineArguments() -> Tuple[str, str]:
    if (len(sys.argv) != 3):
        print('Invalid number of arguments given.')
        sys.exit()
    return (sys.argv[1], sys.argv[2])
