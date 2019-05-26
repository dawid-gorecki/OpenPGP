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
        packet = PGPSecretKeyPacket(packet = packet)

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