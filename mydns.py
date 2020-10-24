from dnsclient import DNSClient
import sys
from typing import Tuple

def getDomainAndRootFromCLI() -> Tuple[str, str]:
    if (len(sys.argv) != 3):
        print('Invalid number of arguments.')
        print('Usage: mydns', 'domain-name', 'root-dns-ip')
        sys.exit()
    domain, root = sys.argv[1], sys.argv[2]
    return (domain, root)

domain, root = getDomainAndRootFromCLI()
myDNSClient = DNSClient(domain, root)
myDNSClient.resolve()
