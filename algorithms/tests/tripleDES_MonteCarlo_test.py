import os, sys
path = os.path.abspath(os.getcwd())
sys.path.append(path)
file_path = path
if os.name == 'nt':
    file_path += '\\algorithms\\tests\\TCFB64Monte3.rsp'
elif os.name == 'posix':
    file_path += '/algorithms/tests/TCFB64Monte3.rsp'
from algorithms.tripleDES import *
import re
import cProfile
import io
import pstats
from pstats import SortKey
import math
file = open(file_path)
keys = [0,0,0]
IV = 0
count = 0
plain = 0
cipher = 0
initializedEncrypt = False
initializedDecrypt = False
print("Monte-Carlo Test")
for line in file:
    if count < 400:    
        if not initializedEncrypt:
            if re.match(r'KEY1', line) != None:
                keys[0] = int("0x"+line[7:23], 16)
            if re.match(r'KEY2', line) != None:
                keys[1] = int("0x"+line[7:23], 16)
            if re.match(r'KEY3', line) != None:
                keys[2] = int("0x"+line[7:23], 16)
            if re.match(r'IV', line) != None:
                IV = int("0x"+line[5:21], 16)
            if re.match(r'PLAINTEXT', line):
                plain = int("0x" + line[12:29], 16)
                initialized = True

        if re.match(r'CIPHERTEXT', line):
            cipher = int("0x" + line[13:30], 16)
            x = 0
            c = []
            pr = cProfile.Profile()
            pr.enable()
            for i in range(10000):
                out = CFBEncrypt(plain.to_bytes(8, "big"), keys, IV, False)
                x = 0
                for i in out:
                    x = (x << 8) | i
                c.append(x)
                plain = IV
                IV = x
            pr.disable()
            s = io.StringIO()
            sortby = SortKey.CUMULATIVE
            ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
            ps.print_stats()
            print(s.getvalue())
            for i in range(3):
                keys[i] = keys[i] ^ c[9999-i]
            
            IV = x
            if(x != cipher):
                print("test nr " + str(count) + " failed!")
                break
            count += 1
    else:
        if not initializedDecrypt:
            if re.match(r'KEY1', line) != None:
                keys[0] = int("0x"+line[7:23], 16)
            if re.match(r'KEY2', line) != None:
                keys[1] = int("0x"+line[7:23], 16)
            if re.match(r'KEY3', line) != None:
                keys[2] = int("0x"+line[7:23], 16)
            if re.match(r'IV', line) != None:
                IV = int("0x"+line[5:21], 16)
            if re.match(r'CIPHERTEXT', line):
                cipher = int("0x" + line[13:30], 16)
                initializedDecrypt = True
        if re.match(r'PLAINTEXT', line):
            plain = int("0x" + line[12:29], 16)
            x = 0
            c = []
            for i in range(10000):
                out = CFBDecrypt(cipher.to_bytes(8, "big"), keys, IV, False)
                x = 0
                for i in out:
                    x = (x << 8) | i
                IV = cipher
                cipher = x ^ cipher
                c.append(x)
            for i in range(3):
                    keys[i] = keys[i] ^ c[9999-i]
            if(x != plain):
                print("test nr " + str(count - 400) + " failed!")
            count += 1
        
        
file.close()