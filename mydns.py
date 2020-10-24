from dnsclient import DNSClient
import sys
from typing import Tuple

def commandLineArguments() -> Tuple[str, str]:
    if (len(sys.argv) != 3):
        print('Invalid number of arguments given.')
        sys.exit()
    domain, root = sys.argv[1], sys.argv[2]
    print('Usage -', domain, '|', root)
    return (domain, root)

domain, root = commandLineArguments()
myDNSClient = DNSClient(domain, root)
myDNSClient.resolve()
