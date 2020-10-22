import socket

def getHeader():
    return b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'

def getQueryMessage(domain):
    labels = domain.split('.')
    lengths = [len(label) for label in labels]
    questionSectionBytes = bytearray(getHeader())
    for label, length in zip(labels, lengths):
        questionSectionBytes.append(length)
        questionSectionBytes.extend(label.encode())
    questionSectionBytes.extend(b'\x00\x00\x01\x00\x01')
    return bytes(questionSectionBytes)

def parseResponseMessage(bytes):
    pass

# c0.nic.me
# a.root-servers.net
# bruceberrios.me: type NS, class IN, ns dns1.registrar-servers.com

# edu: type NS, class IN, ns a.edu-servers.net
# nameserver2.fiu.edu
# goedel.cs.fiu.edu

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.connect(('ns2.google.com', 53))
udp.sendall(getQueryMessage('google.com'))
data = udp.recv(8192)
udp.close()

print(data)
