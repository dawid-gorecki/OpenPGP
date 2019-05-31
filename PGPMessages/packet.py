from .header import PGPHeader, PacketType
from .algo_constants import *
from .key_types import *
from .signature_types import *
from .signature_subpackets import *
from algorithms.DSA import Verify, Sign
from algorithms.SHA512 import Hash
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
        super().__init__()

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

            self.key.fingerprint = self.get_fingerprint()

        else:
            #default values
            raise NotImplementedError('Creating new public key packets not implemented.')
            self.header = PGPHeader()
            self.raw_data = None
            self.version = None
            self.time_created = None
            self.public_key_algo = None
            self.key = None

    def get_fingerprint(self):
        val_to_hash = bytearray()
        val_to_hash += b'\x99'
        val_to_hash += self.header.packet_length.to_bytes(length=2, byteorder='big')
        val_to_hash += self.raw_data[self.header.header_length:]
        h = hashlib.sha1(val_to_hash).digest()
        return int.from_bytes(h, byteorder='big')
        

###############################################################################
#
###############################################################################

class PGPPublicSubkeyPacket(PGPPacket):
    def __init__(self, packet = None):
        super().__init__()

        if packet is not None:
            if packet.header.packet_type != PacketType.PUBLIC_SUBKEY:
                raise ValueError('Packet must be of public subkey type.')

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
            #public key algorithm (currently only Elgamal supported)
            self.public_key_algo = PublicKeyAlgo(self.raw_data[offset])
            offset += 1

            #parse key
            self.key = None
            if self.public_key_algo == PublicKeyAlgo.ELGAMAL_ENCRYPT_ONLY:
                self.key = ElGamalPublicKey()
                self.key.parse_binary(self.raw_data[offset:])
            else:
                raise NotImplementedError('Only DSA public keys implemented for now.')

            self.key.fingerprint = self.get_fingerprint()

        else:
            #default values
            raise NotImplementedError('Creating new public key packets not implemented.')
            self.header = PGPHeader()
            self.raw_data = None
            self.version = None
            self.time_created = None
            self.public_key_algo = None
            self.key = None

    def get_fingerprint(self):
        val_to_hash = bytearray()
        val_to_hash += b'\x99'
        val_to_hash += self.header.packet_length.to_bytes(length=2, byteorder='big')
        val_to_hash += self.raw_data[self.header.header_length:]
        h = hashlib.sha1(val_to_hash).digest()
        return int.from_bytes(h, byteorder='big')

###############################################################################
#
###############################################################################

class PGPPublicKeyEncryptedSessionKeyPacket(PGPPacket):
    def __init__(self, packet = None):
        super().__init__()

        if packet is not None:
            self.header = packet.header
            self.raw_data = packet.raw_data
            offset = self.header.header_length
            self.version = self.raw_data[offset]
            offset += 1
            self.keyID = self.raw_data[offset:offset+8]
            offset += 8
            self.pub_key_algo = PublicKeyAlgo(self.raw_data[offset])
            offset += 1
            self.enc_key = self.raw_data[offset:]
        else:
            self.header = PGPHeader()
            self.raw_data = None
            self.version = 3
            self.keyID = None
            self.pub_key_algo = None
            self.enc_key = None


###############################################################################
#
###############################################################################

class PGPSecretKeyPacket(PGPPacket):
    def __init__(self, packet = None):
        super().__init__()

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
            self.secret_key.pub_key.fingerprint=self.get_fingerprint()
        else:
            raise NotImplementedError('Secret key creation not implemented.')

    def get_fingerprint(self):
        val_to_hash = bytearray()
        #value needed for hashing
        val_to_hash += b'\x99'
        #store public key in temporary variable
        tmp_key = self.secret_key.pub_key.to_bytes()
        #length of version, creation time and public key algorithm fields
        tmp_len = 6
        tmp_len += len(tmp_key)

        #create value for hashing
        val_to_hash += tmp_len.to_bytes(length=2, byteorder='big')
        val_to_hash += self.version.to_bytes(length=1, byteorder='big')
        val_to_hash += self.time_created.to_bytes(length=4, byteorder='big')
        val_to_hash += self.public_key_algo.value.to_bytes(length=1, byteorder='big')
        val_to_hash += tmp_key

        h = hashlib.sha1(val_to_hash).digest()
        return int.from_bytes(h, byteorder='big')

###############################################################################
#
###############################################################################

class PGPSecretSubkeyPacket(PGPPacket):
    def __init__(self, packet = None):
        super().__init__()

        if packet is not None:
            if packet.header.packet_type != PacketType.SECRET_SUBKEY:
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

            if self.public_key_algo == PublicKeyAlgo.ELGAMAL_ENCRYPT_ONLY:
                public_key = ElGamalPublicKey()
                offset += public_key.parse_binary(self.raw_data[offset:])

            else:
                raise NotImplementedError('Only DSA keys currently implemented.')
            
            self.s2k_convention = self.raw_data[offset]
            if self.s2k_convention != 0:
                raise NotImplementedError('No secret key encryption supported.')

            offset += 1

            self.secret_key = ElGamalSecretKey()
            self.secret_key.pub_key = public_key
            offset += self.secret_key.parse_binary(self.raw_data[offset:])
            
            if len(self.raw_data[offset:]) != 2:
                raise ValueError('Checksum too long.')

            self.checksum = int.from_bytes(self.raw_data[offset:], byteorder='big')
            self.secret_key.pub_key.fingerprint=self.get_fingerprint()
        else:
            raise NotImplementedError('Secret key creation not implemented.')

    def get_fingerprint(self):
        val_to_hash = bytearray()
        #value needed for hashing
        val_to_hash += b'\x99'
        #store public key in temporary variable
        tmp_key = self.secret_key.pub_key.to_bytes()
        #length of version, creation time and public key algorithm fields
        tmp_len = 6
        tmp_len += len(tmp_key)

        #create value for hashing
        val_to_hash += tmp_len.to_bytes(length=2, byteorder='big')
        val_to_hash += self.version.to_bytes(length=1, byteorder='big')
        val_to_hash += self.time_created.to_bytes(length=4, byteorder='big')
        val_to_hash += self.public_key_algo.value.to_bytes(length=1, byteorder='big')
        val_to_hash += tmp_key

        h = hashlib.sha1(val_to_hash).digest()
        return int.from_bytes(h, byteorder='big')

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
            self.keyID = int.from_bytes(self.raw_data[self.header.header_length+4 : self.header.header_length+12], byteorder='big')
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

        return_bytes += self.keyID.to_bytes(length=8, byteorder='big')

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
            
            self.hashed_subpackets = []
            hashed_sub_offset = 0

            while hashed_sub_offset < len(self.hashed_subpacket_data_raw):
                subpckt = PGPSignatureSubPckt(self.hashed_subpacket_data_raw[hashed_sub_offset:])
                subpckt = convert_subpckt(subpckt=subpckt)
                hashed_sub_offset += subpckt.header.get_total_length_of_subpacket()
                self.hashed_subpackets.append(subpckt)

            offset += self.hashed_subpacket_length
            self.test = offset
            self.unhashed_subpacket_length = int.from_bytes(self.raw_data[offset:offset+2], byteorder = 'big')
            offset += 2
            self.unhashed_subpacket_data_raw = self.raw_data[offset:offset + self.unhashed_subpacket_length]
            
            self.unhashed_subpackets = []
            unhashed_sub_offset = 0

            while unhashed_sub_offset < len(self.unhashed_subpacket_data_raw):
                subpckt = PGPSignatureSubPckt(self.unhashed_subpacket_data_raw[unhashed_sub_offset:])
                subpckt = convert_subpckt(subpckt=subpckt)
                unhashed_sub_offset += subpckt.header.get_total_length_of_subpacket()
                self.unhashed_subpackets.append(subpckt)

            offset += self.unhashed_subpacket_length
            self.hashed_value_left_bits = self.raw_data[offset: offset+2]
            offset += 2
            self.signature = DSA_Signature()
            self.signature.parse_binary(self.raw_data[offset:])
        else:
            self.version = 4
            self.sig_type = None
            self.pub_key_algo = None
            self.hash_algo = None
            self.hashed_subpacket_length = None
            self.hashed_subpacket_data_raw = None
            self.hashed_subpackets = []
            self.unhashed_subpacket_length = None
            self.unhashed_subpacket_data_raw = None
            self.unhashed_subpackets = []
            self.hashed_value_left_bits = None
            self.signature = DSA_Signature()

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
        for i in self.hashed_subpackets:
            data_to_verify += i.to_bytes()
        hash_len = self.hashed_subpacket_length + 6

        data_to_verify += b'\x04\xff'
        data_to_verify += hash_len.to_bytes(length=4, byteorder='big')

        

        retval = Verify(data_to_verify, key.p_value, key.q_value, key.g_value,
            self.signature.signed_r, self.signature.signed_s, key.y_value, key.q_bits)

        return retval

    def calculate_subpacket_lengths(self):
        unhashed_len = 0
        for packet in self.unhashed_subpackets:
            unhashed_len += packet.header.get_total_length_of_subpacket()
        
        self.unhashed_subpacket_length = unhashed_len

        hashed_len = 0
        for packet in self.hashed_subpackets:
            hashed_len += packet.header.get_total_length_of_subpacket()

        self.hashed_subpacket_length = hashed_len


    def generate_header(self):
        self.header.packet_type = PacketType.SIGNATURE
        #version, public key algo, hash algo, signature type
        length = 4
        #hashed and unhashed subpacket lengths
        length += 4
        #left bytes of hash
        length += 2
        length += self.hashed_subpacket_length
        length += self.unhashed_subpacket_length
        length += len(self.signature.to_bytes())

        self.header.set_length(length)
        

    def generate_onepass(self):
        onepass = PGPOnePassSignaturePacket()
        onepass.version = 3
        onepass.sig_type = self.sig_type
        onepass.pub_key_algo = self.pub_key_algo
        onepass.hash_algo = self.hash_algo
        for subpckt in self.hashed_subpackets:
            if subpckt.header.subpacket_type == SubPacketType.ISSUER:
                onepass.keyID = subpckt.issuerID
        
        if onepass.keyID is None:
            for subpckt in self.unhashed_subpackets:
                if subpckt.header.subpacket_type == SubPacketType.ISSUER:
                    onepass.keyID = subpckt.issuerID

        if onepass.keyID is None:
            raise ValueError('No key ID packet.')
        
        onepass.nested = False
        onepass.generate_header()

        return onepass

    def to_bytes_partial(self):
        ret_bytes = bytearray()
        ret_bytes = self.version.to_bytes(length=1, byteorder='big')
        ret_bytes += self.sig_type.value.to_bytes(length=1, byteorder='big')
        ret_bytes += self.pub_key_algo.value.to_bytes(length=1, byteorder='big')
        ret_bytes += self.hash_algo.value.to_bytes(length=1, byteorder='big')
        ret_bytes += self.hashed_subpacket_length.to_bytes(length=2, byteorder='big')
        for i in self.hashed_subpackets:
            ret_bytes += i.to_bytes()

        return ret_bytes

    def to_bytes(self):
        ret_bytes = bytearray()
        ret_bytes += self.header.to_bytes()
        ret_bytes += self.to_bytes_partial()
        ret_bytes += self.unhashed_subpacket_length.to_bytes(length=2, byteorder='big')
        for i in self.unhashed_subpackets:
            ret_bytes += i.to_bytes()
        ret_bytes += self.hashed_value_left_bits
        ret_bytes += self.signature.to_bytes()

        return ret_bytes

    def __str__(self):
        ret_str = '\n----PGP PACKET----\n'
        ret_str += self.header.__str__()
        ret_str += '\nVersion: ' + str(self.version)
        ret_str += '\nSignature type: ' + str(self.sig_type)
        ret_str += '\nPublic key type: ' + str(self.pub_key_algo)
        ret_str += '\nHash algorithm: ' + str(self.hash_algo)
        ret_str += '\nHashed subpacket length: ' + str(self.hashed_subpacket_length)
        for subpckt in self.hashed_subpackets:
            ret_str += subpckt.__str__() 
        ret_str += '\nUnhashed subpacket length: ' + str(self.unhashed_subpacket_length)
        for subpckt in self.unhashed_subpackets:
            ret_str += subpckt.__str__()
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

    def sign(self, secret_key, user_id):
        #create signature packet
        sig_packet = PGPSignaturePacket()
        #set sig type and algorithm types
        sig_packet.sig_type = SignatureType.BINARY_DOC
        sig_packet.pub_key_algo = PublicKeyAlgo.DSA
        sig_packet.hash_algo = HashAlgo.SHA512

        #add fingerprint subpacket
        fingerprint_subpckt = PGPFingerprintSubPckt()
        fingerprint_subpckt.fingerprint = secret_key.pub_key.fingerprint
        fingerprint_subpckt.generate_header()
        sig_packet.hashed_subpackets.append(fingerprint_subpckt)

        #add creation time subpacket
        time_subpckt = PGPSigCreationSubPckt()
        time_subpckt.created = int(time.time())
        time_subpckt.generate_header()
        sig_packet.hashed_subpackets.append(time_subpckt)

        #add user id packet
        uid_subpckt = PGPSignerUIDSubPckt()
        uid_subpckt.userID = user_id
        uid_subpckt.generate_header()
        sig_packet.hashed_subpackets.append(uid_subpckt)

        #add issuer key id subpacket
        issuer_subpckt = PGPIssuerSubPckt()
        issuer_id = secret_key.pub_key.fingerprint.to_bytes(length=20, byteorder='big')
        issuer_id = issuer_id[-8:]
        issuer_id = int.from_bytes(issuer_id, byteorder='big')
        issuer_subpckt.issuerID = issuer_id
        issuer_subpckt.generate_header()
        sig_packet.unhashed_subpackets.append(issuer_subpckt)

        sig_packet.calculate_subpacket_lengths()

        sig_partial = sig_packet.to_bytes_partial()
        partial_length = len(sig_partial)
        
        data_to_sign = bytearray()
        data_to_sign += self.file_content
        data_to_sign += sig_partial
        data_to_sign += b'\x04\xff'
        data_to_sign += partial_length.to_bytes(length=4, byteorder='big')

        sig_packet.hashed_value_left_bits = Hash(data_to_sign).to_bytes(length=64, byteorder='big')[0:2]
        
        signature = DSA_Signature()
        sig_value = Sign(data_to_sign, secret_key.pub_key.p_value, secret_key.pub_key.q_value,
            secret_key.pub_key.g_value, secret_key.x_value, secret_key.pub_key.q_bits)
        signature.signed_r = sig_value[0]
        signature.signed_s = sig_value[1]
        signature.signed_r_bits = signature.signed_r.bit_length()
        signature.signed_s_bits = signature.signed_s.bit_length()

        sig_packet.signature = signature
        
        sig_packet.generate_header()

        return sig_packet
        
        
    def __str__(self):
        ret_str = '\n----PGP PACKET----\n'
        ret_str += self.header.__str__()
        ret_str += '\nData format: ' + str(self.data_format)
        ret_str += '\nFile name length: ' + str(self.file_name_length)
        ret_str += '\nFile name: "' + str(self.file_name) + '"'
        ret_str += '\nCreated timestamp: ' + str(self.created)
        ret_str += '\n--PGP PACKET END--\n'

        return ret_str

       
###############################################################################
#
###############################################################################


class PGPUserIDPacket(PGPPacket):
    def __init__(self, packet = None):
        super().__init__()

        if packet is not None:
            self.header = packet.header
            self.raw_data = packet.raw_data
            self.userID = self.raw_data[self.header.header_length:self.header.get_total_packet_length()].decode('utf-8')
        else:
            self.header = PGPHeader()
            self.raw_data = None
            self.userID = None
           
