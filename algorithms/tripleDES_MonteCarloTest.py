import tripleDES
import re
import os
print(os.getcwd())
file = open('.//tdesmct/TCFB64Monte3.rsp')
keys = [0,0,0]
IV = 0
count = 0
plain = 0
cipher = 0
print("Variable Key Known Answer Test")
for line in file:
    if count < 400:    
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
        if re.match(r'CIPHERTEXT', line):
            cipher = int("0x" + line[13:30], 16)
            x = 0
            for i in range(10000):
                out = tripleDES.CFBEncrypt(plain.to_bytes(8, "big"), keys, IV, False)
                x = 0
                for i in out:
                    x = (x << 8) | i
                plain = IV
                IV = x
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
            out = tripleDES.CFBDecrypt(cipher.to_bytes(8, "big"), keys, IV, False)
            x = 0
            for i in out:
                x = (x << 8) | i
            print(x == plain)   
            count += 1
        
        
file.close()