from dnsclient import DNSClient
import sys
from typing import Tuple

def getDomainAndRootFromCLI() -> Tuple[str, str]:
    if (len(sys.argv) != 3):
        print(f'Invalid number of arguments expected 2 got {len(sys.argv[1:])}.')
        print('Usage: mydns domain-name root-dns-ip')
        sys.exit()
    domain, root = sys.argv[1], sys.argv[2]
    return (domain, root)

domain, root = getDomainAndRootFromCLI()
myDNSClient = DNSClient(domain, root)
myDNSClient.resolve()
