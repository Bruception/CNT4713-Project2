from dnsclient import DNSClient
import sys
from typing import Tuple

def getDomainAndRootFromCLI() -> Tuple[str, str]:
    if (len(sys.argv) != 3):
        print('Usage: mydns', 'domaine-name', 'root-dns-up')
        sys.exit()
    domain, root = sys.argv[1], sys.argv[2]
    return (domain, root)

domain, root = getDomainAndRootFromCLI()
myDNSClient = DNSClient(domain, root)
myDNSClient.resolve()
