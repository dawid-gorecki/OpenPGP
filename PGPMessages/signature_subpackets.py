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
    ISSUER_FINGERPRINT = 33

SUBPACKET_LENGTHS = (1, 2, 5)

def convert_subpckt(subpckt):
    if subpckt.header.subpacket_type == SubPacketType.ISSUER:
        subpckt = PGPIssuerSubPckt(subPckt = subpckt)
    elif subpckt.header.subpacket_type == SubPacketType.SIG_CREATION_TIME:
        subpckt = PGPSigCreationSubPckt(subPckt = subpckt)
    elif subpckt.header.subpacket_type == SubPacketType.SIGNERS_USER_ID:
        subpckt = PGPSignerUIDSubPckt(subPckt = subpckt)

    return subpckt

class PGPSignatureSubPcktHeader():
    def __init__(self, binary_data=None):
        if binary_data is not None:
            if binary_data[0] <= 192:
                self.subpacket_length = binary_data[0]
                self.length_of_length = 1
            elif binary_data[0] > 192 and binary_data[0] < 255:
                self.subpacket_length = ((binary_data[0] - 192) << 8) + (binary_data[1]) + 192
                self.length_of_length = 2
            elif binary_data[1] == 255:
                self.subpacket_length = int.from_bytes(binary_data[1:5], byteorder='big')
                self.length_of_length = 5
            else:
                raise ValueError('Wrong value of subpacket length')

            if binary_data[self.length_of_length] & 0x80:
                self.subpacket_critical = True
            else:
                self.subpacket_critical = False

            self.subpacket_type = SubPacketType(binary_data[self.length_of_length] & 0x7F)

        else:
            self.subpacket_critical = False
            self.subpacket_length = None
            self.length_of_length = None
            self.subpacket_type = None

    def get_total_length_of_subpacket(self):
        #total_len = self.length_of_length + self.subpacket_length
        total_len = self.get_header_length() + self.subpacket_length - 1
        return total_len

    def get_header_length(self):
        return self.length_of_length + 1

    def set_length(self, length):
        if length > 191:
            raise NotImplementedError('Subpackets of length higher than 192 not implemented.')
        
        self.length_of_length = 1
        self.subpacket_length = length+1

    def to_bytes(self):
        if self.subpacket_length > 192:
            raise NotImplementedError('Subpackets of length bigger than 192 not yet implemented.')

        ret_val = bytearray()

        ret_val += self.subpacket_length.to_bytes(length=1, byteorder='big')

        if self.subpacket_type is None:
            raise ValueError('No subpacket type given.')
        
        if self.subpacket_critical == True:
            tmp = self.subpacket_type.value
            tmp += tmp | 0x80
            ret_val += tmp.to_bytes(length = 1, byteorder='big')
        else:
            ret_val += self.subpacket_type.value.to_bytes(length=1, byteorder='big')
        
        return ret_val  

    def __str__(self):
        ret_str = '\n__HEADER__'
        ret_str += '\nSubpacket length: ' + str(self.subpacket_length-1)
        ret_str += '\nCritical: ' + str(self.subpacket_critical)
        ret_str += '\nSubpacket type: ' + str(self.subpacket_type)
        ret_str += '\n__HEADER_END__\n'
        return ret_str

###############################################################################
# 
###############################################################################   

class PGPSignatureSubPckt():
    def __init__(self, binary_data = None):
        if binary_data is not None:
            self.header = PGPSignatureSubPcktHeader(binary_data = binary_data)
            self.raw_data = binary_data[0:self.header.get_total_length_of_subpacket()]
        else:
            self.header = PGPSignatureSubPcktHeader()
            self.raw_data = None

    def to_bytes(self):
        ret_val = self.raw_data
        return ret_val

    def __str__(self):
        ret_str = '\n__SUBPCKT__'
        ret_str += self.header.__str__()
        ret_str += '__END_SUBPCKT__\n'
        return ret_str

###############################################################################
# 
###############################################################################   

class PGPIssuerSubPckt(PGPSignatureSubPckt):
    def __init__(self, subPckt = None):
        super().__init__()

        if subPckt is not None:
            self.header = subPckt.header

            if self.header.subpacket_type != SubPacketType.ISSUER:
                raise ValueError('Subpacket should have ISSUER type.')

            self.raw_data = subPckt.raw_data
            offset = self.header.get_header_length()
            self.issuerID = int.from_bytes(self.raw_data[offset:offset+8], byteorder='big')
        else:
            self.header = PGPSignatureSubPcktHeader()
            self.raw_data = None
            self.issuerID = None

    def generate_header(self):
        self.header.subpacket_type = SubPacketType.ISSUER
        self.header.set_length(8)

    def to_bytes(self):
        ret_bytes = self.header.to_bytes()
        ret_bytes += self.issuerID.to_bytes(length=8, byteorder='big')
        return ret_bytes

###############################################################################
# 
###############################################################################   

class PGPSigCreationSubPckt(PGPSignatureSubPckt):
    def __init__(self, subPckt = None):
        super().__init__()

        if subPckt is not None:
            self.header = subPckt.header

            if self.header.subpacket_type != SubPacketType.SIG_CREATION_TIME:
                raise ValueError('Subpacket should have SIG_CREATION_TIME type.')

            self.raw_data = subPckt.raw_data
            self.created = int.from_bytes(self.raw_data[self.header.get_header_length():self.header.get_header_length()+4], byteorder='big')
        else:
            self.header = PGPSignatureSubPcktHeader()
            self.raw_data = None
            self.created = None

    def generate_header(self):
        self.header.subpacket_type = SubPacketType.SIG_CREATION_TIME
        self.header.set_length(4)

    def to_bytes(self):
        ret_bytes = self.header.to_bytes()
        ret_bytes += self.created.to_bytes(length=4, byteorder='big')
        return ret_bytes


###############################################################################
# 
###############################################################################   

class PGPSignerUIDSubPckt(PGPSignatureSubPckt):
    def __init__(self, subPckt = None):
        super().__init__()

        if subPckt is not None:
            self.header = subPckt.header

            if self.header.subpacket_type != SubPacketType.SIGNERS_USER_ID:
                raise ValueError('Subpacket should have SIGNERS_USER_ID type.')

            self.raw_data = subPckt.raw_data
            tmp = self.raw_data[self.header.get_header_length():]
            self.userID = tmp.decode('ascii')
        else:
            self.header = PGPSignatureSubPcktHeader()
            self.raw_data = None
            self.userID = None

    def generate_header(self):
        self.header.subpacket_type = SubPacketType.SIGNERS_USER_ID
        self.header.set_length(len(self.userID))

    def to_bytes(self):
        ret_bytes = self.header.to_bytes()
        ret_bytes += self.userID.encode('ascii')
        return ret_bytes

