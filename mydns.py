import socket
import struct

replyCodeMap = {
    0 : 'No error',
    1 : 'Format error',
    2 : 'Server failure',
    3 : 'Name Error',
    4 : 'Not Implemented',
    5 : 'Refused',
}

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

    #   1  2  3  4  5  6  7  8  1  2  3  4  5  6  7  8
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                      ID                       |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    QDCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    ANCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    NSCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    ARCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

def parseResponseMessage(response):
    data = bytearray(response)
    replyCode = data[3] & 0x0F
    questionCount = (data[4] << 8) + data[5];
    answerCount = (data[6] << 8) + data[7];
    nameServerCount = (data[8] << 8) + data[9];
    additionalCount = (data[10] << 8) + data[11];

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.connect(('a.root-servers.net', 53))
udp.sendall(getQueryMessage('cs.fiu.edu'))
data = udp.recv(8192)
udp.close()

parseResponseMessage(data)
