import os, sys
p = os.getcwd()
sys.path.append(p)
from algorithms.tripleDES import *
import re
import math
file = open(p + '/algorithms/tests/TCFB64MMT2.rsp')
keys = [0,0,0]
IV = 0
count = 0
plain = 0
cipher = 0
print("Multiblock Message Test - Decrypt")

for line in file:
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
            print("decryption test nr " + str(count) + " failed!")
        else:
            print("decryption test nr " + str(count) + " passed!")
        count += 1
file.close()