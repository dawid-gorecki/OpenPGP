from PGPMessages.header import PGPHeader, PacketType
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

class OnePassSignatureType(Enum):
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
            

class PGPSignaturePacket(PGPPacket):
    def __init__(self, packet = None):
        super().__init__()

        if packet is not None:
            self.header = packet.header
            self.raw_data  = packet.raw_data
            if self.header.packet_type != PacketType.SIGNATURE:
                raise ValueError('Packet must have signature type.')
