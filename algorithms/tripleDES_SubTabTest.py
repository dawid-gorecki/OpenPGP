from .tripleDES import *
import re
import os

file = open('//home//aigras//crypto//OpenPGP//algorithms//KAT_TDES//TCFB64subtab.rsp')
keys = [0,0,0]
IV = 0
count = 0
plain = 0
cipher = 0
print("Variable Key Known Answer Test")
for line in file:
    if count < 19:    
        if re.match(r'KEYs', line) != None:
            for i in range(3):
                keys[i] = int("0x"+line[7:23], 16)
        if re.match(r'IV', line) != None:
            IV = int("0x"+line[5:21], 16)
        if re.match(r'PLAINTEXT', line):
            plain = int("0x" + line[12:29], 16)
        if re.match(r'CIPHERTEXT', line):
            cipher = int("0x" + line[13:30], 16)
            out = CFBEncrypt(plain.to_bytes(8, "big"), keys, IV, False)
            x = 0
            for i in out:
                x = (x << 8) | i
            print(x == cipher)
            count += 1
    else:
        if re.match(r'KEYs', line) != None:
            for i in range(3):
                keys[i] = int("0x"+line[7:23], 16)
        if re.match(r'IV', line) != None:
            IV = int("0x"+line[5:21], 16)
        if re.match(r'CIPHERTEXT', line):
            cipher = int("0x" + line[13:30], 16)
        if re.match(r'PLAINTEXT', line):
            plain = int("0x" + line[12:29], 16)
            out = CFBDecrypt(cipher.to_bytes(8, "big"), keys, IV, False)
            x = 0
            for i in out:
                x = (x << 8) | i
            print(x == plain)   
            count += 1
        
        
file.close()