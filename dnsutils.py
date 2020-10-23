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
        self.answers = getUShort(data, 6, 7)
        self.nameServers = getUShort(data, 8, 9)
        self.additionalRecords = getUShort(data, 10, 11)

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
        pass

def getUShort(data, byte1, byte2):
    return (data[byte1] << 8) + data[byte2]

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

# Return list of answer rrs
def parseAnswers(data, startByte, answers):
    return 0

# Return list of authority rrs
def parseNameServers(data, startByte, nameServers):
    return 0

# Return list of additional rrs
def parseAdditionalRecords(data, startByte, additionalRecords):
    return 0

# Return a DNSMessage
def parseDNSResponse(data):
    dnsMessage = DNSMessage()
    dnsMessage.setHeader(data)
    answers = dnsMessage.header.answers
    nameServers = dnsMessage.header.nameServers
    additionalRecords = dnsMessage.header.additionalRecords
    nextByte = skipQuestionSection(data)
    if (answers > 0):
        nextByte = parseAnswers(data, nextByte, answers)
    if (nameServers > 0):
        nextByte = parseNameServers(data, nextByte, nameServers)
    if (additionalRecords > 0):
        nextByte = parseAdditionalRecords(data, nextByte, additionalRecords)
    return dnsMessage
    