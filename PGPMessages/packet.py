from .header import PGPHeader, PacketType
from .algo_constants import *
from .key_types import *
from .signature_types import *
from algorithms.DSA import Verify, Hash
import hashlib
from enum import Enum
import time

###############################################################################
#
###############################################################################

class PGPPacket():
    ''' PGP Packet base class. '''
    def __init__(self, binary_data = None):
        self.header = PGPHeader()
        self.total_length = None
        self.raw_data = None

        if binary_data is not None:
            self.header.parse_binary(binary_data)
            self.total_length = self.header.get_total_packet_length()
            self.raw_data = binary_data[0 : self.total_length]

    def __str__(self):
        ret_str = '\n----PGP PACKET----\n'
        ret_str += self.header.__str__()
        ret_str += '\nTotal packet length: ' + str(self.header.get_total_packet_length())
        ret_str += '\n--PGP PACKET END--\n'
        return ret_str
        

###############################################################################
#
###############################################################################

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

###############################################################################
#
###############################################################################

class PGPPublicKeyPacket(PGPPacket):
    def __init__(self, packet = None):
        if packet is not None:
            if packet.header.packet_type != PacketType.PUBLIC_KEY:
                raise ValueError('Packet must be of public key type.')

            #copy values    
            self.header = packet.header
            self.raw_data = packet.raw_data

            #set offset for the rest of parsing
            offset = self.header.header_length
            #packet version (should be 4)
            self.version = self.raw_data[offset]
            if self.version != 4:
                raise NotImplementedError('Only version 4 packets implemented.')
            
            offset += 1
            #time of creation
            self.time_created = int.from_bytes(self.raw_data[offset : offset+4], byteorder='big')
            offset += 4
            #public key algorithm (currently only DSA supported)
            self.public_key_algo = PublicKeyAlgo(self.raw_data[offset])
            offset += 1

            #parse key
            self.key = None
            if self.public_key_algo == PublicKeyAlgo.DSA:
                self.key = DSAPublicKey()
                self.key.parse_binary(self.raw_data[offset:])
            else:
                raise NotImplementedError('Only DSA public keys implemented for now.')

        else:
            #default values
            self.header = None
            self.raw_data = None
            self.version = None
            self.time_created = None
            self.public_key_algo = None
            self.key = None

###############################################################################
#
###############################################################################

class PGPSecretKeyPacket(PGPPacket):
    def __init__(self, packet = None):
        if packet is not None:
            if packet.header.packet_type != PacketType.SECRET_KEY:
                raise ValueError('Packet must be of secret key type.')
            
            self.header = packet.header
            self.raw_data = packet.raw_data

            offset = self.header.header_length

            self.version = self.raw_data[offset]
            offset += 1
            if self.version != 4:
                raise NotImplementedError('Only version 4 packets now implemented.')

            self.time_created = int.from_bytes(self.raw_data[offset:offset+4], byteorder='big')
            offset += 4

            self.public_key_algo = PublicKeyAlgo(self.raw_data[offset])
            offset += 1

            public_key = None

            if self.public_key_algo == PublicKeyAlgo.DSA:
                public_key = DSAPublicKey()
                offset += public_key.parse_binary(self.raw_data[offset:])
            else:
                raise NotImplementedError('Only DSA keys currently implemented.')
            
            self.s2k_convention = self.raw_data[offset]
            if self.s2k_convention != 0:
                raise NotImplementedError('No secret key encryption supported.')

            offset += 1

            self.secret_key = DSASecretKey()
            self.secret_key.pub_key = public_key
            offset += self.secret_key.parse_binary(self.raw_data[offset:])
            
            if len(self.raw_data[offset:]) != 2:
                raise ValueError('Checksum too long.')

            self.checksum = int.from_bytes(self.raw_data[offset:], byteorder='big')


###############################################################################
#
###############################################################################

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
            #set default values
            self.version = None
            self.sig_type = None
            self.hash_algo = None
            self.pub_key_algo = None
            self.keyID = None
            self.nested = None

    def generate_header(self):
        self.header.packet_type = PacketType.ONEPASS_SIGNATURE
        #version field
        packet_length = 1
        #signature type
        packet_length += 1
        #hash algorithm
        packet_length += 1
        #public key algorithm
        packet_length += 1
        #key ID
        packet_length += 8
        #nested
        packet_length += 1
        self.header.set_length(packet_length)

    def to_bytes(self):
        if self.header is None:
            raise ValueError('Packet must contain ore.')

        return_bytes = self.header.to_bytes()

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

###############################################################################
# 
###############################################################################            

class PGPSignaturePacket(PGPPacket):
    def __init__(self, packet = None):
        super().__init__()

        if packet is not None:
            self.header = packet.header
            self.raw_data  = packet.raw_data
            if self.header.packet_type != PacketType.SIGNATURE:
                raise ValueError('Packet must have signature type.')
            self.version = self.raw_data[self.header.header_length]
            if self.version != 4:
                raise NotImplementedError('Only version 4 signature packets supported.')
            self.sig_type = SignatureType(self.raw_data[self.header.header_length+1])
            self.pub_key_algo = PublicKeyAlgo(self.raw_data[self.header.header_length+2])
            self.hash_algo = HashAlgo(self.raw_data[self.header.header_length+3])
            offset = self.header.header_length + 4
            self.hashed_subpacket_length = int.from_bytes(self.raw_data[offset: offset + 2], byteorder = 'big')
            offset = offset + 2

            #currently ignoring subpackets
            self.hashed_subpacket_data_raw = self.raw_data[offset:offset + self.hashed_subpacket_length]
            offset += self.hashed_subpacket_length
            self.test = offset
            self.unhashed_subpacket_length = int.from_bytes(self.raw_data[offset:offset+2], byteorder = 'big')
            offset += 2
            self.unhashed_subpacket_data_raw = self.raw_data[offset:offset + self.unhashed_subpacket_length]
            offset += self.unhashed_subpacket_length
            self.hashed_value_left_bits = self.raw_data[offset: offset+2]
            offset += 2
            self.signature = DSA_Signature()
            self.signature.parse_binary(self.raw_data[offset:])
        else:
            self.header = None
            self.raw_data = None
            self.version = None
            self.sig_type = None
            self.pub_key_algo = None
            self.hash_algo = None
            self.hashed_subpacket_length = None
            self.hashed_subpacket_data_raw = None
            self.unhashed_subpacket_length = None
            self.unhashed_subpacket_data_raw = None
            self.hashed_value_left_bits = None
            self.signature = None

    def verify(self, data_packet, key):
        if not isinstance(data_packet, PGPLiteralDataPacket):
            raise TypeError('Data packet must be of literal data type.')

        if not isinstance(key, DSAPublicKey):
            raise TypeError('Key must be of public key type.')

        data_to_verify = bytearray()
        data_to_verify += data_packet.file_content
        data_to_verify += self.version.to_bytes(length=1, byteorder='big')
        data_to_verify += self.sig_type.value.to_bytes(length=1, byteorder='big')
        data_to_verify += self.pub_key_algo.value.to_bytes(length=1, byteorder='big')
        data_to_verify += self.hash_algo.value.to_bytes(length=1, byteorder='big')
        data_to_verify += self.hashed_subpacket_length.to_bytes(length=2, byteorder='big')
        data_to_verify += self.hashed_subpacket_data_raw
        hash_len = self.hashed_subpacket_length + 6
        data_to_verify += b'\x04\xff'
        data_to_verify += hash_len.to_bytes(length=4, byteorder='big')

        return Verify(data_to_verify, key.p_value, key.q_value, key.g_value,
            self.signature.signed_r, self.signature.signed_s, key.y_value, key.q_bits)

    def generate_onepass(self):
        onepass = PGPOnePassSignaturePacket()
        onepass.version = self.version
        onepass.sig_type = self.sig_type
        onepass.pub_key_algo = self.pub_key_algo
        onepass.hash_algo = self.hash_algo
        
        onepass.nested = False

    def __str__(self):
        ret_str = '\n----PGP PACKET----\n'
        ret_str += self.header.__str__()
        ret_str += '\nVersion: ' + str(self.version)
        ret_str += '\nSignature type: ' + str(self.sig_type)
        ret_str += '\nPublic key type: ' + str(self.pub_key_algo)
        ret_str += '\nHash algorithm: ' + str(self.hash_algo)
        ret_str += '\nHashed subpacket length: ' + str(self.hashed_subpacket_length) 
        ret_str += '\nUnhashed subpacket length: ' + str(self.unhashed_subpacket_length)
        ret_str += '\nLeft 2 bytes of hash: ' + str(self.hashed_value_left_bits)
        ret_str += '\n--PGP PACKET END--\n'
        return ret_str
        
###############################################################################
#
###############################################################################

class LiteralDataFormat(Enum):
    ''' Literal data packets data format constants. '''
    BINARY_FORMAT = 0x62
    TEXT_FORMAT = 0x74
    UNICODE_FORMAT = 0x75

###############################################################################
#
###############################################################################

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

    def __str__(self):
        ret_str = '\n----PGP PACKET----\n'
        ret_str += self.header.__str__()
        ret_str += '\nData format: ' + str(self.data_format)
        ret_str += '\nFile name length: ' + str(self.file_name_length)
        ret_str += '\nFile name: "' + str(self.file_name) + '"'
        ret_str += '\nCreated timestamp: ' + str(self.created)
        ret_str += '\n--PGP PACKET END--\n'

        return ret_str
       
            
           
