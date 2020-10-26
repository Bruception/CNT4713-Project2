from typing import Tuple, List
import random

MAX_MESSAGE_SIZE = 512

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
    def __init__(self, recordData):
        self.name = recordData['name']
        self.rtype = recordData['rtype']
        self.rclass = recordData['rclass']
        self.ttl = recordData['ttl']
        self.rdlength = recordData['rdlength']
        self.rdata = recordData['rdata']

    def __str__(self):
        return f'\tName : {self.name}\tData : {self.rdata}'

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
            currentByte += 2
            break
        labelBuffer = []
        for i in range(0, labelLength):
            labelBuffer.append(chr(data[currentByte + i + 1]))
        nameBuffer.append(''.join(labelBuffer))
        currentByte += labelLength + 1
    return ('.'.join(nameBuffer), currentByte)

def parseIP(data, byte) -> str:
    return '.'.join([str(data[byte + b]) for b in range(0, 4)])

def recordIsAdditional(recordData) -> bool:
    return recordData['rtype'] == 1 and recordData['rclass'] == 1

def recordIsAuthoritative(recordData) -> bool:
    return recordData['rtype'] == 2 and recordData['rclass'] == 1

# Return list of resource records
def parseResourceRecords(data, startByte, numRecords) -> Tuple[List[ResourceRecord], int]:
    currentByte = startByte
    recordsParsed = 0
    records = []
    while (recordsParsed < numRecords):
        info = parseName(data, currentByte)
        currentByte = info[1]
        recordData = {
            'name' : info[0],
            'rtype' : getUShort(data, currentByte),
            'rclass' : getUShort(data, currentByte + 2),
            'ttl' : getUInt(data, currentByte + 4),
            'rdlength' : getUShort(data, currentByte + 8),
            'rdata' : None,
        }
        currentByte += 10
        if (recordIsAdditional(recordData)):
            recordData['rdata'] = parseIP(data, currentByte)
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
        info = parseResourceRecords(data, nextByte, answers)
        dnsMessage.setAnswers(info[0])
        nextByte = info[1]
    if (nameServers > 0):
        info = parseResourceRecords(data, nextByte, nameServers)
        dnsMessage.setAuthority(info[0])
        nextByte = info[1]
    if (additionalRecords > 0):
        info = parseResourceRecords(data, nextByte, additionalRecords)
        dnsMessage.setAdditional(info[0])
    return dnsMessage
