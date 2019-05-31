import os, sys
path = os.path.abspath(os.getcwd())
sys.path.append(path)
file_path = path
if os.name == 'nt':
    file_path += '\\algorithms\\tests\\TCFB64MMT3.rsp'
elif os.name == 'posix':
    file_path += '/algorithms/tests/TCFB64MMT3.rsp'
from algorithms.tripleDES import *
import re
import math
file = open(file_path)
keys = [0,0,0]
IV = 0
count = 0
plain = 0
cipher = 0
print("Multiblock Message Test - Encrypt and Decrypt")

for line in file:
    if count < 10:    
        if re.match(r'KEY1', line) != None:
            keys[0] = int("0x"+line[7:23], 16)
        if re.match(r'KEY2', line) != None:
            keys[1] = int("0x"+line[7:23], 16)
        if re.match(r'KEY3', line) != None:
            keys[2] = int("0x"+line[7:23], 16)
        if re.match(r'IV', line) != None:
            IV = int("0x"+line[5:21], 16)
        if re.match(r'PLAINTEXT', line):
            plain = int("0x" + line[12:], 16)
        if re.match(r'CIPHERTEXT', line):
            cipher = int("0x" + line[13:], 16)
            x = 0
            out = CFBEncrypt(plain.to_bytes(math.ceil(plain.bit_length()/8), "big"), keys, IV, False)
            x = 0
            for i in out:
                x = (x << 8) | i
            if(x != cipher):
                print("encryption test nr " + str(count) + " failed!")
            else:
                print("encryption test nr " + str(count) + " passed!")
            count += 1
    else:
        if re.match(r'KEY1', line) != None:
            keys[0] = int("0x"+line[7:23], 16)
        if re.match(r'KEY2', line) != None:
            keys[1] = int("0x"+line[7:23], 16)
        if re.match(r'KEY3', line) != None:
            keys[2] = int("0x"+line[7:23], 16)
        if re.match(r'IV', line) != None:
            IV = int("0x"+line[5:21], 16)
        if re.match(r'CIPHERTEXT', line):
            cipher = int("0x" + line[13:], 16)
        if re.match(r'PLAINTEXT', line):
            plain = int("0x" + line[12:], 16)
            x = 0
            out = CFBDecrypt(cipher.to_bytes(math.ceil(cipher.bit_length()/8), "big"), keys, IV, False)
            x = 0
            for i in out:
                x = (x << 8) | i
            if(x != plain):
                print("decryption test nr " + str(count-10) + " failed!")
            else:
                print("decryption test nr " + str(count-10) + " passed!")
            count += 1


file.close()