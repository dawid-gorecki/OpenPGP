from .packet import *
from .header import PacketType
from algorithms.tripleDES import CFBEncrypt, CFBDecrypt
from algorithms.ElGamal import Encrypt
from secrets import randbits

def convert_packet(packet):
    if packet.header.packet_type == PacketType.LITERAL_DATA:
        packet = PGPLiteralDataPacket(packet = packet)
    elif packet.header.packet_type == PacketType.ONEPASS_SIGNATURE:
        packet = PGPOnePassSignaturePacket(packet = packet)
    elif packet.header.packet_type == PacketType.SIGNATURE:
        packet = PGPSignaturePacket(packet = packet)
    elif packet.header.packet_type == PacketType.SECRET_KEY:
        packet = PGPSecretKeyPacket(packet = packet)
    elif packet.header.packet_type == PacketType.PUBLIC_KEY:
        packet = PGPPublicKeyPacket(packet = packet)
    elif packet.header.packet_type == PacketType.USER_ID:
        packet = PGPUserIDPacket(packet = packet)
    elif packet.header.packet_type == PacketType.PUBLIC_SUBKEY:
        packet = PGPPublicSubkeyPacket(packet = packet)
    elif packet.header.packet_type == PacketType.SECRET_SUBKEY:
        packet = PGPSecretSubkeyPacket(packet = packet)
    elif packet.header.packet_type == PacketType.PK_ENCRYPTED_SESSION_KEY:
        packet = PGPPublicKeyEncryptedSessionKeyPacket(packet = packet)
    elif packet.header.packet_type == PacketType.SYM_ENCRYPTED_DATA:
        packet = PGPSymEncryptedDataPacket(packet = packet)

    return packet

class PGPMessage():
    def __init__(self):
        self.packets = []

    def from_bytes(self, data_bytes):
        offset = 0

        while offset < len(data_bytes):
            packet = PGPPacket(binary_data=data_bytes[offset:])
            offset += packet.header.get_total_packet_length()
            packet = convert_packet(packet)
            self.packets.append(packet)

    def open_data_file(self, filename):

        if len(self.packets) != 0:
            raise Exception('PGP message already has packets.')

        packet = PGPLiteralDataPacket()
        packet.read_file(filename)
        self.packets.append(packet)

    def open_pgp_file(self, filename):

        if len(self.packets) != 0:
            raise Exception('PGP message already has packets.')

        data = None
        with open(filename, 'rb') as inFile:
            data = inFile.read()

        offset = 0

        while offset < len(data):
            packet = PGPPacket(binary_data=data[offset:])
            offset += packet.header.get_total_packet_length()
            packet = convert_packet(packet)
            self.packets.append(packet)

    def list_packets(self):
        for packet in self.packets:
            print(packet)

    def get_public_key(self):
        pub_key = None
        for packet in self.packets:
            if packet.header.packet_type == PacketType.PUBLIC_KEY:
                pub_key = packet.key
                break
            elif packet.header.packet_type == PacketType.SECRET_KEY:
                pub_key = packet.secret_key.pub_key
                break

        return pub_key

    def get_public_subkey(self):
        pub_subkey = None

        for packet in self.packets:
            if packet.header.packet_type == PacketType.PUBLIC_SUBKEY:
                pub_subkey = packet.key
                break
            elif packet.header.packet_type == PacketType.SECRET_SUBKEY:
                pub_subkey = packet.secret_key.pub_key
                break

        return pub_subkey

    def get_user_ID(self):
        uid_packet = None
        for packet in self.packets:
            if packet.header.packet_type == PacketType.USER_ID:
                uid_packet = packet
                break

        if uid_packet is None:
            raise RuntimeError('User ID packet not found.')

        return uid_packet.userID
        

    def get_secret_key(self):
        secret_key = None
        for packet in self.packets:
            if packet.header.packet_type == PacketType.SECRET_KEY:
                secret_key = packet.secret_key
                break

        return secret_key

    def get_secret_subkey(self):
        secret_subkey = None
        for packet in self.packets:
            if packet.header.packet_type == PacketType.SECRET_SUBKEY:
                secret_subkey = packet.secret_key
                break

        return secret_subkey

    def get_session_key(self, key_msg):
        session_key_pckt = None
        for packet in self.packets:
            if packet.header.packet_type == PacketType.PK_ENCRYPTED_SESSION_KEY:
                session_key_pckt = packet
                break

        return session_key_pckt.decrypt_key(key_msg.get_secret_subkey())

    def unpack_message(self, filename):
        for packet in self.packets:
            if packet.header.packet_type == PacketType.LITERAL_DATA:
                with open(filename, 'wb') as outfile:
                    outfile.write(packet.file_content)
                break


    def verify_message(self, key_msg):

        if not isinstance(key_msg, PGPMessage):
            raise TypeError('Key message not of message type.')

        data_packet = None
        sig_packet = None
        for packet in self.packets:
            if packet.header.packet_type == PacketType.LITERAL_DATA:
                data_packet = packet
            elif (data_packet is not None) and packet.header.packet_type == PacketType.SIGNATURE:
                sig_packet = packet
                break


        if data_packet is not None and sig_packet is not None:
            verified = sig_packet.verify(data_packet, key_msg.get_public_key())
            if verified:
                print("Message verified succesfully.")
            else:
                print("Message verification failed.")

            return verified
            
        else:
            raise ValueError('Message contains no signature or no data.')

    def sign_message(self, key_msg):
        if len(self.packets) == 0:
            raise ValueError('Message must have data packet.')
        if len(self.packets) > 1:
            raise ValueError('Signing messages with more than one message packet is not supported.')

        if not isinstance(self.packets[0], PGPLiteralDataPacket):
            raise TypeError('Packet must be of literal data type.')

        retval = self.packets[0].sign(key_msg.get_secret_key(), key_msg.get_user_ID())
        self.packets.append(retval)
        self.packets.insert(0, retval.generate_onepass())

    def decrypt_message(self, key_msg):
        session_key = self.get_session_key(key_msg)
        
        enc_packet = None
        for packet in self.packets:
            if packet.header.packet_type == PacketType.SYM_ENCRYPTED_DATA:
                enc_packet = packet
                break

        if enc_packet is None:
            print('No encrypted data found.')

        return enc_packet.decrypt(session_key)
        

    def write_gpg_file(self, filename):
        with open(filename, 'wb') as outFile:
            data = bytearray()
            for packet in self.packets:
                data += packet.to_bytes()

            outFile.write(data)

    def encrypt_message(self, key_msg):
        public_key = key_msg.get_public_subkey()

        data = bytearray()
        for packet in self.packets:
            data += packet.to_bytes()

        keys = []
        for i in range(3):
            keys.append(randbits(64))

        enc_data = bytearray(CFBEncrypt(data, keys))

        enc_data = int.from_bytes(enc_data, byteorder='big')
        
        


        

        


    
        

        

        
        
