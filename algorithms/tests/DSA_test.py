import os, sys
p = os.getcwd()
sys.path.append(p)
from algorithms.DSA import Sign
import re
import math
matchFound = False
file = open(p + "/algorithms/tests/SigGen.txt")
count = 0
for line in file:
    if re.match(r'\[mod = L=(1024|2048|3072), N=(160|224|256), SHA-512\]', line)!=None:
            matchFound = True
            L = int(line[9:13])
            N = int(line[17:20])
            print("Testing DSA signature generation with L = " + str(L) + ", N = " + str(N))
            count = 0
    if matchFound == True:
        if re.match(r'P = ', line) != None:
            P = int("0x"+line[4:L], 16)
            #print(hex(P))
        elif re.match(r'Q = ', line) != None:
            Q = int("0x"+line[4:N], 16)
            #print(hex(Q))
        elif re.match(r'G = ', line) != None:
            G = int("0x"+line[4:L], 16)
            #print(hex(G))
        elif re.match(r'Msg =', line) != None:
            Msg = int("0x"+line[6:L], 16)
            #print(hex(Msg))
        elif re.match(r'X = ', line) != None:
            X = int("0x"+line[4:N], 16)
            #print(hex(X))
        elif re.match(r'Y = ', line) != None:
            Y = int("0x"+line[4:L], 16)
            #print(hex(Y))
        elif re.match(r'K = ', line) != None:
            K = int("0x"+line[4:N], 16)
            #print(hex(K))
        elif re.match(r'R = ', line) != None:
            R = int("0x"+line[4:N], 16)
            #print(hex(R))
        elif re.match(r'S = ', line) != None:
            S = int("0x"+line[4:N], 16)
            #print(hex(S))
            count += 1
            print("Starting test nr " + str(count))
            MsgBytes = Msg.to_bytes(math.ceil(Msg.bit_length()/8), "big")
            MsgBytes = bytearray(MsgBytes)
            (rOut, sOut) = Sign(MsgBytes, P, Q, G, X, N, K)
            # print(hex(rOut))
            # print(hex(R))
            # print(hex(sOut))
            # print(hex(S))
            if rOut == R and sOut == S:
                print("Test nr " + str(count) + " passed")
            if count == 15:
                matchFound = False
        
file.close()