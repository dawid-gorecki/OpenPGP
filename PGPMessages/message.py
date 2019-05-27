from .packet import *
from .header import PacketType

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

    return packet

class PGPMessage():
    def __init__(self):
        self.packets = []

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

    def get_secret_key(self):
        secret_key = None
        for packet in self.packets:
            if packet.header.packet_type == PacketType.SECRET_KEY:
                secret_key = packet.secret_key

        return secret_key

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
        else:
            raise ValueError('Message contains no signature or no data.')