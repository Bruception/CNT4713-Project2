from dnsclient import DNSClient, commandLineArguments

domain, root = commandLineArguments()
myDNSClient = DNSClient(domain, root)
myDNSClient.resolve()
