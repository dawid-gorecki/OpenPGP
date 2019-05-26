from enum import Enum
import math

class PacketFormat(Enum):
    OLD_PACKET = 0
    NEW_PACKET = 1

class PacketType(Enum):
    PK_ENCRYPTED_SESSION_KEY = 1
    SIGNATURE = 2
    SK_ENCRYPTED_SESSION_KEY = 3
    ONEPASS_SIGNATURE = 4
    SECRET_KEY = 5
    PUBLIC_KEY = 6
    SECRET_SUBKEY = 7
    COMPRESSED_DATA = 8
    SYM_ENCRYPTED_DATA = 9
    MARKER = 10
    LITERAL_DATA = 11
    TRUST = 12
    USER_ID = 13
    PUBLIC_SUBKEY = 14
    USER_ATTR = 17
    SYM_ENCR_AND_INTEGRITY_PROTECTED_DATA = 18
    MODIFICATION_DETECTION_CODE = 19


OLD_TYPE_HEADER_LENGTHS = (2, 3, 5, 1)


class PGPHeader():
    def __init__(self, *args, **kwargs):
        self.packet_format = PacketFormat.OLD_PACKET
        self.packet_type = None
        self.header_length = None
        self.packet_length = None

    def parse_binary(self, data):
        if not (data[0] & 0x80):
            raise ValueError('Not a PGP packet.')
        
        self.packet_format = PacketFormat((data[0] & 0x40) >> 6)
        
        if self.packet_format == PacketFormat.NEW_PACKET:
            raise NotImplementedError('New packet formats currently not supported.')

        elif self.packet_format == PacketFormat.OLD_PACKET:
            self.packet_type = PacketType((data[0] & 0x3C) >> 2)
            self.header_length = OLD_TYPE_HEADER_LENGTHS[data[0] & 0x03]
            
            if self.header_length == 1:
                self.packet_length = None
            elif self.header_length == 2:
                self.packet_length = data[1]
            else:
                self.packet_length = int.from_bytes(data[1:self.header_length], byteorder='big')

    def set_length(self, packet_length):
        if packet_length > 2 ** 32:
            raise ValueError('Packet too long.')

        self.packet_length = packet_length
        
        packet_length_min_bits = math.ceil(math.log2(packet_length))
        packet_length_min_bytes = math.ceil(packet_length_min_bits / 8)
        
        if packet_length_min_bytes == 3:
            packet_length_min_bytes = 4

        self.header_length = packet_length_min_bytes + 1
        

    def get_total_packet_length(self):
        if self.header_length == 1:
            raise ValueError('Packet length unknown')
        else:
            return self.header_length + self.packet_length

    def to_bytes(self):
        if self.packet_format is None:
            raise ValueError('Packet format must be set.')
        if self.packet_format == PacketFormat.NEW_PACKET:
            raise NotImplementedError('New packet formats not yet implemented.')
        if self.packet_type is None:
            raise ValueError('Packet type must be set.')
        if self.header_length is None:
            raise ValueError('Header length must be set')
        if self.header_length != 1 and self.packet_length is None:
            raise ValueError('If header length is known packet length must be set.')

        header_first_byte = 0x80

        if not isinstance(self.packet_type, PacketType):
            raise ValueError('Packet type must be of type PacketType')

        header_first_byte = header_first_byte | (self.packet_type.value << 2)


        if not (self.header_length in OLD_TYPE_HEADER_LENGTHS):
            raise ValueError('Length of the packet must have precise length.')

        header_first_byte = header_first_byte | (OLD_TYPE_HEADER_LENGTHS.index(self.header_length))

        retVal = bytearray()

        retVal.append(header_first_byte)

        if self.header_length != 1:
            additional_bytes = int.to_bytes(self.packet_length, byteorder='big', length=self.header_length-1)
            for i in additional_bytes:
                retVal.append(i)

        return retVal


    def __str__(self):
        ret_str = '----HEADER----\n'
        ret_str += 'Packet format: ' + str(self.packet_format)
        ret_str += '\nHeader length: ' + self.header_length
        ret_str += '\nPacket type: ' + self.packet_type
        ret_str += '\nPacket length' + self.packet_length
        ret_str += '\n--HEADER END--'

        return ret_str
        
