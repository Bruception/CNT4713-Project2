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

QUERY_HEADER = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'

class DNSHeader:
    def __init__(self, data):
        self.answers = getUShort(data, 6)
        self.nameServers = getUShort(data, 8)
        self.additionalRecords = getUShort(data, 10)

    def __str__(self):
        answers = f'\t{self.answers} Answers.'
        nameServers = f'\t{self.nameServers} Intermediate Name Servers.'
        additionalRecords = f'\t{self.additionalRecords} Additional Information Records.'
        return '\n'.join([answers, nameServers, additionalRecords])

class ResourceRecord:
    def __init__(self):
        self.name = None
        self.type = None
        self.rclass = None
        self.ttl = None
        self.rdlength = None
        self.rdata = None

class DNSMessage:
    def __init__(self):
        self.header = None
        self.answers = None
        self.authority = None
        self.additional = None

    def setHeader(self, data):
        self.header = parseResponseHeader(data)
    
    def setAnswers(self, answers):
        pass

    def setAuthority(self, authority):
        pass

    def setAdditional(self, additional):
        pass

    def __str__(self):
        return str(self.header)

def getUShort(data, byte):
    return (data[byte] << 8) + data[byte + 1]

def getUInt(data, byte):
    return (data[byte] << 32) + (data[byte + 1] << 16) + (data[byte + 2] << 8)  + data[byte + 3]

def getQueryMessage(domain) -> bytes:
    labels = domain.split('.')
    lengths = [len(label) for label in labels]
    questionSectionBytes = bytearray(QUERY_HEADER)
    for label, length in zip(labels, lengths):
        questionSectionBytes.append(length)
        questionSectionBytes.extend(label.encode())
    questionSectionBytes.extend(b'\x00\x00\x01\x00\x01')
    return bytes(questionSectionBytes)

def parseResponseHeader(response):
    data = bytearray(response)
    dnsHeader = DNSHeader(data)
    return dnsHeader

def skipQuestionSection(data):
    currentByteIndex = 12
    while (data[currentByteIndex] != 0):
        labelLength = data[currentByteIndex]
        currentByteIndex += labelLength + 1
    return currentByteIndex + 5 # Start of the Answers sections

def parseName(data, byte):
    currentByte = byte
    nameBuffer = []
    while (data[currentByte] != 0):
        labelLength = data[currentByte]
        if ((labelLength & 0xC0) == 0xC0): # This is a pointer
            byteOffset = ((data[currentByte] & 0x3F) << 8) + data[currentByte + 1]
            nameBuffer.append(parseName(data, byteOffset)[0])
            currentByte += 2
            break
        labelBuffer = []
        for i in range(0, labelLength):
            labelBuffer.append(chr(data[currentByte + i + 1]))
        nameBuffer.append(''.join(labelBuffer))
        currentByte += labelLength + 1
    return ('.'.join(nameBuffer), currentByte)

# Return list of resource records
def parseResourceRecords(data, startByte, numRecords):
    currentByte = startByte
    recordsParsed = 0
    records = []
    while (recordsParsed < numRecords):
        info = parseName(data, currentByte)
        recordName = info[0]
        currentByte = info[1]
        rtype = getUShort(data, currentByte) # 2 bytes
        rclass = getUShort(data, currentByte + 2) # 2 bytes
        ttl = getUInt(data, currentByte + 4) # 4 bytes
        rdlength = getUShort(data, currentByte + 8) # 2 bytes
        print(recordName, rtype, rclass, ttl, rdlength)
        currentByte += rdlength + 10
        recordsParsed += 1
    return currentByte

# Return a DNSMessage
def parseDNSResponse(data):
    dnsMessage = DNSMessage()
    dnsMessage.setHeader(data)
    answers = dnsMessage.header.answers
    nameServers = dnsMessage.header.nameServers
    additionalRecords = dnsMessage.header.additionalRecords
    nextByte = skipQuestionSection(data)
    if (answers > 0):
        nextByte = parseResourceRecords(data, nextByte, answers)
    if (nameServers > 0):
        nextByte = parseResourceRecords(data, nextByte, nameServers)
    if (additionalRecords > 0):
        nextByte = parseResourceRecords(data, nextByte, additionalRecords)
    return dnsMessage
