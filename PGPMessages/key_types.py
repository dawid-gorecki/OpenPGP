import math

class DSAPublicKey():
    def __init__(self):
        self.fingerprint = None
        self.p_bits = None
        self.p_value = None
        self.q_bits = None
        self.q_value = None
        self.g_bits = None
        self.g_value = None
        self.y_bits = None
        self.y_value = None

    def parse_binary(self, binary_data):
        self.p_bits = int.from_bytes(binary_data[0:2], byteorder='big')
        offset = 2
        p_bytes = math.ceil(self.p_bits / 8)
        self.p_value = int.from_bytes(binary_data[offset : offset + p_bytes], byteorder='big')
        offset += p_bytes

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

        #return offset
        return p_bytes + q_bytes + g_bytes + y_bytes + 8

    def key_total_length(self):
        bytes_needed = lambda a: math.ceil(a / 8)
        #length of all length fields
        total_length = 8
        #length of values
        total_length += bytes_needed(self.p_bits) + bytes_needed(self.q_bits)
        total_length += bytes_needed(self.g_bits)
        total_length += bytes_needed(self.y_bits)
        
        return total_length

    def to_bytes(self):
        bytes_needed = lambda a: math.ceil(a / 8)
        #r bits and r
        byte_return = bytearray()
        byte_return += self.p_bits.to_bytes(length=2, byteorder = 'big')
        byte_return += self.p_value.to_bytes(length=bytes_needed(self.p_bits), byteorder = 'big')

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
        self.pub_key = None
        self.x_bits = None
        self.x_value = None

    def parse_binary(self, binary_data):
        self.x_bits = int.from_bytes(binary_data[0:2], byteorder='big')
        x_bytes = math.ceil(self.x_bits / 8)
        self.x_value = int.from_bytes(binary_data[2:2+x_bytes], byteorder='big')

        return x_bytes + 2

class ElGamalPublicKey():
    def __init__(self):
        self.fingerprint = None
        self.p_bits = None
        self.p_value = None
        self.g_bits = None
        self.g_value = None
        self.y_bits = None
        self.y_value = None

    def parse_binary(self, binary_data):
        bytes_needed = lambda a: math.ceil(a / 8)
        
        self.p_bits = int.from_bytes(binary_data[0:2], byteorder='big')
        p_bytes = bytes_needed(self.p_bits)
        self.p_value = int.from_bytes(binary_data[2:2+p_bytes], byteorder='big')
        offset = 2 + p_bytes

        self.g_bits = int.from_bytes(binary_data[offset:offset+2], byteorder='big')
        offset += 2
        g_bytes = bytes_needed(self.g_bits)
        self.g_value = int.from_bytes(binary_data[offset:offset+g_bytes], byteorder='big')
        offset += g_bytes

        self.y_bits = int.from_bytes(binary_data[offset:offset+2], byteorder='big')
        offset += 2
        y_bytes = bytes_needed(self.y_bits)
        self.y_value = int.from_bytes(binary_data[offset:offset+y_bytes], byteorder='big')

        return p_bytes + g_bytes + y_bytes + 6

    def to_bytes(self):
        bytes_needed = lambda a: math.ceil(a / 8)

        ret_bytes = bytearray()
        ret_bytes += self.p_bits.to_bytes(length=2, byteorder='big')
        ret_bytes += self.p_value.to_bytes(length=bytes_needed(self.p_bits), byteorder='big')

        ret_bytes += self.g_bits.to_bytes(length=2, byteorder='big')
        ret_bytes += self.g_value.to_bytes(length=bytes_needed(self.g_bits), byteorder='big')
        
        ret_bytes += self.y_bits.to_bytes(length=2, byteorder='big')
        ret_bytes += self.y_value.to_bytes(length=bytes_needed(self.y_bits), byteorder='big')

        return ret_bytes

class ElGamalSecretKey():
    def __init__(self):
        self.pub_key = None
        self.x_bits = None
        self.x_value = None

    def parse_binary(self, binary_data):
        bytes_needed = lambda a: math.ceil(a / 8)

        self.x_bits = int.from_bytes(binary_data[0:2], byteorder='big')
        x_bytes = bytes_needed(self.x_bits)
        self.x_value = int.from_bytes(binary_data[2:2+x_bytes], byteorder='big')

        return x_bytes + 2

class ElGamalEncryptedSessionKey():
    def __init__(self):
        self.gkmodp_bits = None
        self.gkmodp_value = None
        self.mykmodp_bits = None
        self.mykmodp_value = None

    def parse_binary(self, binary_data):
        bytes_needed = lambda a: math.ceil(a / 8)

        self.gkmodp_bits = int.from_bytes(binary_data[0:2], byteorder='big')
        gkmodp_bytes = bytes_needed(self.gkmodp_bits)
        self.gkmodp_value = int.from_bytes(binary_data[2:2+gkmodp_bytes], byteorder='big')
        offset = 2 + gkmodp_bytes

        self.mykmodp_bits = int.from_bytes(binary_data[offset:offset+2], byteorder='big')
        mykmodp_bytes = bytes_needed(self.mykmodp_bits)
        offset += 2
        self.mykmodp_value = int.from_bytes(binary_data[offset:offset+mykmodp_bytes], byteorder='big')
        offset += mykmodp_bytes

        return gkmodp_bytes + mykmodp_bytes + 4

    def to_bytes(self):
        ret_bytes = bytearray()
        ret_bytes += self.gkmodp_bits.to_bytes(length=2, byteorder='big')
        gkmodp_bytes = math.ceil(self.gkmodp_bits / 8)
        ret_bytes += self.gkmodp_value(length=gkmodp_bytes, byteorder='big')
        
        ret_bytes += self.mykmodp_bits(length=2, byteorder='big')
        mykmodp_bytes = math.ceil(self.mykmodp_bits / 8)
        ret_bytes += self.mykmodp_value(length=mykmodp_bytes, byteorder='big')

        return ret_bytes

    def get_total_key_length(self):
        gkmod_bytes = math.ceil(self.gkmodp_bits / 8)
        mykmod_bytes = math.ceil(self.mykmodp_bits / 8)

        return gkmod_bytes + mykmod_bytes + 4
        