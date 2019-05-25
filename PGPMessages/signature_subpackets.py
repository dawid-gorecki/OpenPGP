from enum import Enum

class SubPacketType(Enum):
    SIG_CREATION_TIME = 2
    SIG_EXPIRATION_TIME = 3
    EXPORTABLE_CERT = 4
    TRUST_SIG = 5
    REGEX = 6
    REVOCABLE = 7
    KEY_EXPIRATION_TIME = 9
    PREFFERED_SYM_ALGO = 11
    REVOCATION_KEY = 12
    ISSUER = 16
    NOTATION_DATA = 20
    PREFFERED_HASH_ALGO = 21
    PREFFERED_COMPRESSION_ALGO = 22
    KEY_SERVER_PREFERENCES = 23
    PREFFERED_KEY_SERVER = 24
    PRIMARY_USER_ID = 25
    POLICY_URI = 26
    KEY_FLAGS = 27
    SIGNERS_USER_ID = 28
    REASON_FOR_REVOCATION = 29
    FEATURES = 30
    SIG_TARGET = 31
    EMBEDDED_SIG = 32

SUBPACKET_LENGTHS = (1, 2, 5)

class PGPSignatureSubPcktHeader():
    def __init__(self, binary_data=None):
        if binary_data is not None:
            if binary_data[0] & 0x80:
                self.subpacket_critical = True
            else:
                self.subpacket_critical = False

            type_offset = None
            self.subpacket_type = SubPacketType(binary_data[0] & 0x7F)

            if binary_data[1] <= 192:
                self.subpacket_length = binary_data[1]
                self.length_of_length = 1
            elif binary_data[1] > 192 and binary_data < 255:
                self.subpacket_length = ((binary_data[1] - 192) << 8) + (binary_data[2]) + 192
                self.length_of_length = 2
            elif binary_data[1] == 255:
                self.subpacket_length = int.from_bytes(binary_data[2:6], byteorder='big')
                self.length_of_length = 5
            else:
                raise ValueError('Wrong value of subpacket length')
        else:
            self.subpacket_critical = False
            self.subpacket_length = None
            self.length_of_length = None
            self.subpacket_type = None

    def get_total_length_of_subpacket(self):
        total_len = 0

    def to_bytes(self):
        if self.subpacket_length > 192:
            raise NotImplementedError('Subpackets of length bigger than 192 not yet implemented.')

        
        

class PGPSignatureSubPckt():
    def __init__(self, binary_data = None):
        if binary_data is not None:
            self.header = PGPSignatureSubPcktHeader(binary_data = binary_data)
            self.raw_data = binary_data
        else:
            self.header = PGPSignatureSubPcktHeader()
            self.raw_data = None

    def to_bytes(self):
        raise NotImplementedError('Subpacket creation not implemented.')


