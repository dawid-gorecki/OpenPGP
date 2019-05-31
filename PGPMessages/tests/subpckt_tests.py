from random import randint, choice
import os, sys
path = os.path.abspath(os.getcwd())
sys.path.append(path)
file_path = path

from PGPMessages.signature_subpackets import *

def header_test():
    for i in range(1000):
        test_length =  SUBPACKET_LENGTHS[randint(0,2)]
        test_data = []
        test_subpckt_length = 0
        if test_length == 1:
            test_data.append(randint(0,192))
            test_subpckt_length = test_data[0]
        elif test_length == 2:
            test_data.append(randint(193, 254))
            test_data.append(randint(0,255))
            test_subpckt_length =((test_data[0]-192)<<8) + test_data[1] + 192
        elif test_length == 5:
            test_data.append(255)
            for i in range(4):
                test_data.append(randint(0,255))
                test_subpckt_length = (test_subpckt_length << 8) + test_data[i+1]
        ptype = choice(list(SubPacketType))
        test_data.append(ptype.value)
        test_packet = PGPSignatureSubPcktHeader(bytearray(test_data))

        for elem in test_data:
            if test_packet.subpacket_length != test_subpckt_length:
                print("got subpacket length: " +test_packet.subpacket_length+ " expected: " + test_subpckt_length )
                return False
            if test_packet.subpacket_critical != (test_data[test_length] & 0x80):
                print("got subpacket_critical = " + test_packet.subpacket_critical + " expected: " + test_data[test_length] & 0x80)
                return False
            if test_packet.subpacket_type != ptype:
                print("got subpacket_type: " + test_packet.subpacket_type.name + " expected: " + ptype.name)
                return False
            if test_packet.length_of_length != test_length:
                return False
    return True

def fingerprint_subpckt_test():
    for i in range(1000):
        test_length =  1#SUBPACKET_LENGTHS[randint(0,2)]
        test_data = []
        test_subpckt_length = 0
        if test_length == 1:
            test_data.append(randint(1,192))
            test_subpckt_length = test_data[0]
        elif test_length == 2:
            test_data.append(randint(193, 254))
            test_data.append(randint(0,255))
            test_subpckt_length =((test_data[0]-192)<<8) + test_data[1] + 192
        elif test_length == 5:
            test_data.append(255)
            for i in range(4):
                test_data.append(randint(0,255))
                test_subpckt_length = (test_subpckt_length << 8) + test_data[i+1]
        ptype = SubPacketType.ISSUER_FINGERPRINT
        test_data.append(ptype.value)
        print(test_subpckt_length)
        for i in range(test_subpckt_length):
            test_data.append(randint(0,255))
        test_packet = PGPSignatureSubPckt(test_data)
        test_packet = PGPFingerprintSubPckt(test_packet)
        #test_packet.generate_header()
    return True
print(fingerprint_subpckt_test())