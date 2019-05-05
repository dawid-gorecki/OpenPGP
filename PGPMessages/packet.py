from PGPMessages.header import PGPHeader, PacketType
from PGPMessages.algo_constants import *
from enum import Enum

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
            self.hash_algo = self.raw_data[self.header.header_length+2]
            self.pub_key_algo = self.raw_data[self.header.header_length+3]
            self.keyID = self.raw_data[self.header.header_length+4 : self.header.header_length+12]
            if self.raw_data[self.header.header_length+13] == 0:
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

            

class PGPSignaturePacket(PGPPacket):
    def __init__(self, packet = None):
        super().__init__()

        if packet is not None:
            self.header = packet.header
            self.raw_data  = packet.raw_data
            if self.header.packet_type != PacketType.SIGNATURE:
                raise ValueError('Packet must have signature type.')

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
                    + 2 + self.file_name_length]
            current_offset = self.header.header_length + 2 + self.file_name_length
            self.created = self.raw_data[current_offset : current_offset + 4]
            self.created = int.from_bytes(self.created, byteorder='big')
            current_offset = current_offset + 4
            self.file_content = self.raw_data[current_offset : -1]
        else:
            self.data_format = None
            self.file_name_length = None
            self.file_name = None
            self.created = None
            self.file_content = None

    def to_bytes(self):
        pass
            
            
            
            
