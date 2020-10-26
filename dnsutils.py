from typing import Tuple, List
import random

MAX_MESSAGE_SIZE = 512

RESPONSE_CODE_MAP = {
    0: 'No error',
    1: 'Format error',
    2: 'Server failure',
    3: 'Name error',
    4: 'Not implemented',
    5: 'Refused',
}

class DNSHeader:
    def __init__(self, data):
        self.answers = getUShort(data, 6)
        self.nameServers = getUShort(data, 8)
        self.additionalRecords = getUShort(data, 10)
        self.isTruncated = ((data[2] & 0x02) == 0x02)
        self.responseCode = data[3] & 0x0F

    def __str__(self):
        responseMessage = f'\tResponse Code: {self.responseCode} - {RESPONSE_CODE_MAP[self.responseCode]}.'
        truncated = '\tWarning: Message is truncated.' if self.isTruncated else ''
        answers = f'\t{self.answers} Answers.'
        nameServers = f'\t{self.nameServers} Intermediate Name Servers.'
        additionalRecords = f'\t{self.additionalRecords} Additional Information Records.'
        return '\n'.join(filter(None, [responseMessage, truncated, answers, nameServers, additionalRecords]))

class ResourceRecord:
    def __init__(self, recordData):
        self.name = recordData['name']
        self.rtype = recordData['rtype']
        self.rclass = recordData['rclass']
        self.ttl = recordData['ttl']
        self.rdlength = recordData['rdlength']
        self.rdata = recordData['rdata']
        self.label = 'Name Server' if recordIsAuthoritative(recordData) else 'IP'

    def __str__(self):
        return f'\tName : {self.name}\t{self.label} : {self.rdata}'

class DNSMessage:
    def __init__(self):
        self.header = None
        self.answers = []
        self.authority = []
        self.additional = []

    def setHeader(self, data):
        self.header = parseResponseHeader(data)

    def setAnswers(self, answers):
        self.answers = answers

    def setAuthority(self, authority):
        self.authority = authority

    def setAdditional(self, additional):
        self.additional = additional

    def __str__(self):
        buffer = []
        buffer.append('Reply received. Content overview:')
        buffer.append(str(self.header))
        buffer.append('Answers section:')
        buffer.extend(formatRecords(self.answers))
        buffer.append('Authoritive Section:')
        buffer.extend(formatRecords(self.authority))
        buffer.append('Additional Information Section:')
        buffer.extend(formatRecords(self.additional))
        return '\n'.join(buffer)

def getBeginningOfHeader() -> bytearray:
    byteValues = bytearray([random.randint(0, 255), random.randint(0, 255)])
    byteValues.extend(b'\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00')
    return byteValues

def formatRecords(records):
    return [str(record) for record in records]

def getUShort(data, byte) -> int:
    return (data[byte] << 8) + data[byte + 1]

def getUInt(data, byte) -> int:
    return (data[byte] << 32) + (data[byte + 1] << 16) + (data[byte + 2] << 8)  + data[byte + 3]

def getQueryMessage(domain) -> bytes:
    labels = domain.split('.')
    lengths = [len(label) for label in labels]
    messageBytes = getBeginningOfHeader()
    for label, length in zip(labels, lengths):
        messageBytes.append(length)
        messageBytes.extend(label.encode())
    messageBytes.extend(b'\x00\x00\x01\x00\x01')
    return bytes(messageBytes)

def parseResponseHeader(response) -> DNSHeader:
    data = bytearray(response)
    dnsHeader = DNSHeader(data)
    return dnsHeader

def skipQuestionSection(data) -> int:
    currentByteIndex = 12
    while (data[currentByteIndex] != 0):
        labelLength = data[currentByteIndex]
        currentByteIndex += labelLength + 1
    return currentByteIndex + 5 # Start of the Answers sections

def parseName(data, byte) -> Tuple[str, int]:
    currentByte = byte
    nameBuffer = []
    while (data[currentByte] != 0):
        labelLength = data[currentByte]
        if ((labelLength & 0xC0) == 0xC0): # This is a pointer
            byteOffset = ((data[currentByte] & 0x3F) << 8) + data[currentByte + 1]
            nameBuffer.append(parseName(data, byteOffset)[0])
            # Only increment by 1 because pointers do not end with the null octet
            currentByte += 1
            break
        labelBuffer = []
        for i in range(0, labelLength):
            labelBuffer.append(chr(data[currentByte + i + 1]))
        nameBuffer.append(''.join(labelBuffer))
        currentByte += labelLength + 1
    return ('.'.join(nameBuffer), currentByte + 1)

def recordIsAdditional(recordData):
    return recordData['rtype'] == 1 and recordData['rclass'] == 1

def recordIsAuthoritative(recordData):
    return recordData['rtype'] == 2 and recordData['rclass'] == 1

# Return list of resource records
def parseResourceRecords(data, startByte, numRecords) -> Tuple[List[ResourceRecord], int]:
    currentByte = startByte
    recordsParsed = 0
    records = []
    while (recordsParsed < numRecords):
        name, currentByte = parseName(data, currentByte)
        recordData = {
            'name' : name,
            'rtype' : getUShort(data, currentByte),
            'rclass' : getUShort(data, currentByte + 2),
            'ttl' : getUInt(data, currentByte + 4),
            'rdlength' : getUShort(data, currentByte + 8),
            'rdata' : None,
        }
        currentByte += 10
        if (recordIsAdditional(recordData)):
            parsedIP = '.'.join([str(data[currentByte + b]) for b in range(0, 4)])
            recordData['rdata'] = parsedIP
        elif (recordIsAuthoritative(recordData)):
            recordData['rdata'] = parseName(data, currentByte)[0]
        currentByte += recordData['rdlength']
        if (recordData['rdata']):
            records.append(ResourceRecord(recordData))
        recordsParsed += 1
    return (records, currentByte)

# Return a DNSMessage
def parseDNSResponse(data) -> DNSMessage:
    dnsMessage = DNSMessage()
    dnsMessage.setHeader(data)
    answers = dnsMessage.header.answers
    nameServers = dnsMessage.header.nameServers
    additionalRecords = dnsMessage.header.additionalRecords
    nextByte = skipQuestionSection(data)
    if (answers > 0):
        records, nextByte = parseResourceRecords(data, nextByte, answers)
        dnsMessage.setAnswers(records)
    if (nameServers > 0):
        records, nextByte = parseResourceRecords(data, nextByte, nameServers)
        dnsMessage.setAuthority(records)
    if (additionalRecords > 0):
        records, nextByte = parseResourceRecords(data, nextByte, additionalRecords)
        dnsMessage.setAdditional(records)
    return dnsMessage
