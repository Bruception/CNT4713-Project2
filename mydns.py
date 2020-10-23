import socket

responseCodeMap = {
    0 : 'No error',
    1 : 'Format error',
    2 : 'Server failure',
    3 : 'Name Error',
    4 : 'Not Implemented',
    5 : 'Refused',
}

qTypeMap = {
    1 : 'A',
    2 : 'NS',
}

qClassMap = {
    1 : 'IN',
    2 : 'CS',
    3 : 'CH',
    4 : 'HS',
}

def getUShort(data, byte1, byte2):
    return (data[byte1] << 8) + data[byte2]

responseHeaderMap = {
    'transactionID'     : lambda data : getUShort(data, 0, 1),
    'queryResponse'     : lambda data : (data[2] & 0x80) >> 7,
    'responseCode'      : lambda data : data[3] & 0x0F,
    'questions'         : lambda data : getUShort(data, 4, 5),
    'answers'           : lambda data : getUShort(data, 6, 7),
    'nameServers'       : lambda data : getUShort(data, 8, 9),
    'additionalRecords' : lambda data : getUShort(data, 10, 11),
}

class DNSHeader:
    def __init__(self, data):
        for field in responseHeaderMap:
            setattr(self, field, responseHeaderMap[field](data))

    def __str__(self):
        buffer = []
        buffer.append('DNS Header')
        for attr in vars(self):
            buffer.append(''.join(['\t', attr, ': ', str(getattr(self, attr))]))
        return '\n'.join(buffer)

def getHeader():
    return b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'

def getQueryMessage(domain) -> bytes:
    labels = domain.split('.')
    lengths = [len(label) for label in labels]
    questionSectionBytes = bytearray(getHeader())
    for label, length in zip(labels, lengths):
        questionSectionBytes.append(length)
        questionSectionBytes.extend(label.encode())
    questionSectionBytes.extend(b'\x00\x00\x01\x00\x01')
    return bytes(questionSectionBytes)

def parseResponseHeader(response) -> DNSHeader:
    data = bytearray(response)
    dnsHeader = DNSHeader(data)
    return dnsHeader

def parseQuestion(data):
    currentByteIndex = 12
    domainNameBuffer = []
    while (data[currentByteIndex] != 0):
        labelLength = data[currentByteIndex]
        labelBuffer = []
        for i in range(0, labelLength):
            labelBuffer.append(chr(data[currentByteIndex + i + 1]))
        domainNameBuffer.append(''.join(labelBuffer))
        currentByteIndex += labelLength + 1
    domainName = '.'.join(domainNameBuffer)
    qType = getUShort(data, currentByteIndex + 1, currentByteIndex + 2)
    qClass = getUShort(data, currentByteIndex + 3, currentByteIndex + 4)
    print(domainName, qTypeMap[qType], qClassMap[qClass])
    return currentByteIndex + 5 # Start of the Answers sections

def parseAnswers(data):
    pass

def parseNameServers(data):
    pass

def parseAdditionalRecords(data):
    pass

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.connect(('a.root-servers.net', 53))
udp.sendall(getQueryMessage('cs.fiu.edu'))
data = udp.recv(8192)
udp.close()

print(data)

dnsHeader = parseResponseHeader(data)
print(dnsHeader)
parseQuestion(data)
