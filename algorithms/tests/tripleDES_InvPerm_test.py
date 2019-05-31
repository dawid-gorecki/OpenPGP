import os, sys
path = os.path.abspath(os.getcwd())
sys.path.append(path)
file_path = path
if os.name == 'nt':
    file_path += '\\algorithms\\tests\\TCFB64invperm.rsp'
elif os.name == 'posix':
    file_path += '/algorithms/tests/TCFB64invperm.rsp'
from algorithms.tripleDES import *
import re

file = open(file_path)
keys = [0,0,0]
IV = 0
count = 0
plain = 0
cipher = 0
print("Inverse Permutation test")
print("Output should be all 0s")
for line in file:
    if re.match(r'KEYs', line) != None:
        for i in range(3):
            keys[i] = int("0x"+line[7:23], 16)
    if re.match(r'IV', line) != None:
        IV = int("0x"+line[5:21], 16)
    if re.match(r'PLAINTEXT', line):
        plain = int("0x" + line[12:29], 16)
    if re.match(r'CIPHERTEXT', line):
        cipher = int("0x" + line[13:30], 16)
        if(count < 64):
            out = CFBEncrypt(plain.to_bytes(8, "big"), keys, IV, False)
        else:
            out = CFBDecrypt(cipher.to_bytes(8, "big"), keys, IV, False)
        #print(hex(IV))
        #print(hex(plain))
        #print(hex(cipher))
        #print(hex(keys[0]))
        #print(count)
        print(out)
        count += 1    
        
file.close()