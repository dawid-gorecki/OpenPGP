from PGPMessages.header import PGPHeader, PacketType
from PGPMessages.algo_constants import *
from enum import Enum
import time

class PGPPacket():
    def __init__(self, binary_data = None):
        self.header = PGPHeader()
        self.total_length = None
        self.raw_data = None

        if binary_data is not None:
            self.header.parse_binary(binary_data)
            self.total_length = self.header.get_total_packet_length()
            self.raw_data = binary_data[0 : self.total_length]

class SignatureType(Enum):
    BINARY_DOC = 0x00
    CANONICAL_TEXT_DOC = 0x01
    STANDALONE_SIG = 0x02
    GENERIC_CERT_UID_PUB_KEY_PCKT = 0x10
    PERSONA_CERT_UID_PUB_KEY_PCKT = 0x11
    CASUAL_CERT_UID_PUB_KEY_PCKT = 0x12
    POSITIVE_CERT_UID_PUB_KEY_PCKT = 0x13
    SUBKEY_BINDING_SIG = 0x18
    PRIMARY_KEY_BINDING_SIG = 0x19
    SIG_DIRECTLY_ON_KEY = 0x1F
    KEY_REVOCATION_SIG = 0x20
    SUBKEY_REVOC_SIG = 0x28
    CERT_REVOC_SIG = 0x30
    TIMESTAMP_SIG = 0x40
    THIRD_PARTY_CONFIRM_SIG = 0x50

class PGPOnePassSignaturePacket(PGPPacket):
    def __init__(self, packet = None):
        super().__init__()

        if packet is not None:
            self.header = packet.header
            self.raw_data  = packet.raw_data
            if self.header.packet_type != PacketType.ONEPASS_SIGNATURE:
                raise ValueError('Packet must have one-pass signature type.')  
            self.version = self.raw_data[self.header.header_length]
            self.sig_type = SignatureType(self.raw_data[self.header.header_length+1])
            self.hash_algo = HashAlgo(self.raw_data[self.header.header_length+2])
            self.pub_key_algo = PublicKeyAlgo(self.raw_data[self.header.header_length+3])
            self.keyID = self.raw_data[self.header.header_length+4 : self.header.header_length+12]
            if self.raw_data[self.header.header_length+12] == 0:
                self.nested = True
            else:
                self.nested = False
        else:
            self.version = None
            self.sig_type = None
            self.hash_algo = None
            self.pub_key_algo = None
            self.keyID = None
            self.nested = None

    def to_bytes(self):
        if self.header is None:
            raise ValueError('Packet must contain ore.')

        return_bytes = self.headet.to_bytes()

        if self.version is None:
            self.version = 3

        return_bytes.append(self.version)

        if self.sig_type is None:
            raise ValueError('Signature type must be set.')

        return_bytes.append(self.sig_type.value)

        if self.hash_algo is None:
            raise ValueError('Hash algorithm must be set.')

        return_bytes.append(self.hash_algo.value)

        if self.pub_key_algo is None:
            raise ValueError('Public key algorithm must be set.')
        
        return_bytes.append(self.pub_key_algo.value)

        if self.keyID is None:
            raise ValueError('Key ID must be set.')

        for i in self.keyID:
            return_bytes.append(i)

        if self.nested == True:
            return_bytes.append(0)
        else:
            return_bytes.append(1)

        return return_bytes

            

class PGPSignaturePacket(PGPPacket):
    def __init__(self, packet = None):
        super().__init__()

        if packet is not None:
            self.header = packet.header
            self.raw_data  = packet.raw_data
            if self.header.packet_type != PacketType.SIGNATURE:
                raise ValueError('Packet must have signature type.')
            self.version = self.raw_data[self.header.header_length]
            self.sig_type = SignatureType[self.raw_data[self.header.header_length+1]]
            self.pub_key_algo = PublicKeyAlgo(self.raw_data[self.header.header_length+2])
            self.hash_algo = HashAlgo(self.raw_data[self.header.header_length+3])


class LiteralDataFormat(Enum):
    BINARY_FORMAT = 0x62
    TEXT_FORMAT = 0x74
    UNICODE_FORMAT = 0x75

class PGPLiteralDataPacket(PGPPacket):
    def __init__(self, packet = None):
        super().__init__()

        if packet is not None:
            self.header = packet.header
            self.raw_data = packet.raw_data
            if self.header.packet_type != PacketType.LITERAL_DATA:
                raise ValueError('Packet must have literal data type.')

            self.data_format = LiteralDataFormat(self.raw_data[self.header.header_length])
            self.file_name_length = self.raw_data[self.header.header_length + 1]
            current_offset = self.header.header_length + 2
            self.file_name = self.raw_data[current_offset : self.header.header_length 
                    + 2 + self.file_name_length].decode("utf-8")
            current_offset = self.header.header_length + 2 + self.file_name_length
            self.created = self.raw_data[current_offset : current_offset + 4]
            self.created = int.from_bytes(self.created, byteorder='big')
            current_offset = current_offset + 4
            self.file_content = self.raw_data[current_offset : len(self.raw_data)]
        else:
            self.data_format = None
            self.file_name_length = None
            self.file_name = None
            self.created = None
            self.file_content = None

    def to_bytes(self):
        if self.header is None:
            raise ValueError('No header created.')

        return_bytes = self.header.to_bytes()

        if self.data_format is None:
            raise ValueError('Data format must be set.')

        if self.data_format != LiteralDataFormat.BINARY_FORMAT:
            raise NotImplementedError('Data types other than binary not yet implemented.')

        
        return_bytes.append(self.data_format.value)
        return_bytes.append(self.file_name_length)

        for c in self.file_name:
            return_bytes.append(ord(c))

        tmp = int.to_bytes(self.created, byteorder='big', length=4)

        for i in tmp:
            return_bytes.append(i)

        for i in self.file_content:
            return_bytes.append(i)
        
        return return_bytes

    def generate_header(self):
        self.header.packet_type = PacketType.LITERAL_DATA
        #data format
        packet_length = 1
        #file name length and file name
        packet_length += (self.file_name_length) + 1
        #created date
        packet_length += 4
        #file content length
        packet_length += len(self.file_content)
        self.header.set_length(packet_length)

    def read_file(self, filename):
        with open(filename, 'rb') as inFile:
            data_array = inFile.read()
            self.file_name = filename
            self.file_content = data_array
            self.data_format = LiteralDataFormat.BINARY_FORMAT
            self.file_name_length = len(filename)
            self.created = int(time.time())
        
        self.generate_header()

            
            
            
           
