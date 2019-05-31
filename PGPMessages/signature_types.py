import math

class DSA_Signature():
    def __init__(self):
        self.signed_r_bits = None
        self.signed_r = None
        self.signed_s_bits = None
        self.signed_s = None

    def parse_binary(self, binary_data):

        bytes_needed = lambda x: math.ceil(x / 8)

        #r bits and r value
        self.signed_r_bits = int.from_bytes(binary_data[0:2], byteorder='big')
        offset = 2
        self.signed_r = int.from_bytes(binary_data[offset : offset+bytes_needed(self.signed_r_bits)],
            byteorder='big')
        offset += bytes_needed(self.signed_r_bits)

        #s bits and s value
        self.signed_s_bits = int.from_bytes(binary_data[offset:offset+2], byteorder='big')
        offset += 2
        self.signed_s = int.from_bytes(binary_data[offset:offset+bytes_needed(self.signed_s_bits)],
            byteorder='big')


    def to_bytes(self):
        bytes_needed = lambda x: math.ceil(x / 8)

        return_bytes = bytearray()

        return_bytes += self.signed_r_bits.to_bytes(length=2, byteorder='big')
        r_bytes = bytes_needed(self.signed_r_bits)
        return_bytes += self.signed_r.to_bytes(length=r_bytes, byteorder='big')

        return_bytes += self.signed_s_bits.to_bytes(length=2, byteorder='big')
        s_bytes = bytes_needed(self.signed_s_bits)
        return_bytes += self.signed_s.to_bytes(length=s_bytes, byteorder = 'big')

        return return_bytes