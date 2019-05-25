import math

class DSAPublicKey():
    def __init__(self):
        self.r_bits = None
        self.r_value = None
        self.q_bits = None
        self.q_value = None
        self.g_bits = None
        self.g_value = None
        self.y_bits = None
        self.y_value = None

    def parse_binary(self, binary_data):
        self.r_bits = int.from_bytes(binary_data[0:2], byteorder='big')
        offset = 2
        r_bytes = math.ceil(self.r_bits / 8)
        self.r_value = int.from_bytes(binary_data[offset : offset + r_bytes], byteorder='big')
        offset += r_bytes

        self.q_bits = int.from_bytes(binary_data[offset: offset + 2], byteorder='big')
        q_bytes = math.ceil(self.q_bits / 8)
        offset += 2
        self.q_value = int.from_bytes(binary_data[offset: offset + q_bytes], byteorder='big')
        offset += q_bytes

        self.g_bits = int.from_bytes(binary_data[offset:offset+2], byteorder='big')
        g_bytes = math.ceil(self.g_bits / 8)
        offset += 2
        self.g_value = int.from_bytes(binary_data[offset: offset + g_bytes], byteorder='big')
        offset += g_bytes
        
        self.y_bits = int.from_bytes(binary_data[offset:offset+2], byteorder='big')
        y_bytes = math.ceil(self.y_bits / 8)
        offset += 2
        self.y_value = int.from_bytes(binary_data[offset:offset+y_bytes], byteorder='big')

    def to_bytes(self):
        bytes_needed = lambda a: math.ceil(a / 8)
        #r bits and r
        byte_return = bytearray()
        byte_return += self.r_bits.to_bytes(length=2, byteorder = 'big')
        byte_return += self.r_value.to_bytes(length=bytes_needed(self.r_bits), byteorder = 'big')

        #number of q bits and q value
        byte_return += self.q_bits.to_bytes(length=2, byteorder = 'big')
        byte_return += self.q_value.to_bytes(length=bytes_needed(self.q_bits), byteorder = 'big')

        #number of g bits and g value
        byte_return += self.g_bits.to_bytes(length=2, byteorder = 'big')
        byte_return += self.g_value.to_bytes(length=bytes_needed(self.g_bits), byteorder = 'big')

        #number of y bits and y value
        byte_return += self.y_bits.to_bytes(length=2, byteorder = 'big')
        byte_return += self.y_value.to_bytes(length=bytes_needed(self.y_bits), byteorder='big')

        return byte_return

class DSASecretKey():
    def __init__(self):
        pass