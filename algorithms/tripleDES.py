#tripleDES.py
#implementation of TripleDES algorithm
import secrets
#import aux
from math import ceil
IP = [58,  50,  42,  34,  26,  18,  10,  2,
     60,  52,  44, 36,  28,  20,  12,  4,
      62,  54,  46,  38,  30,  22,  14,  6,
       64, 56, 48,  40,  32,  24,  16,  8,
        57,  49,  41,  33,  25,  17,    9,  1,
         59,  51,  43,  35,  27,  19,  11,  3,
          61,  53,  45,  37,  29,  21,  13,  5,
           63,  55,  47,  39,  31,  23,  15, 7]
invIP = [40, 8, 48, 16, 56, 24, 64, 32,
         39, 7, 47, 15, 55, 23, 63, 31,
         38, 6, 46, 14, 54, 22, 62, 30,
         37, 5, 45, 13, 53, 21, 61, 29,
         36, 4, 44, 12, 52, 20, 60, 28,
         35, 3, 43, 11, 51, 19, 59, 27,
         34, 2, 42, 10, 50, 18, 58, 26,
         33, 1, 41, 9, 49, 17, 57,  25]
E = [32, 1, 2, 3, 4, 5,
      4, 5, 6, 7, 8, 9,
      8, 9, 10, 11, 12, 13,
      12, 13, 14, 15, 16, 17,
      16, 17, 18, 19, 20, 21,
      20, 21, 22, 23, 24, 25,
      24, 25, 26, 27, 28, 29,
      28, 29, 30, 31, 32, 1]
P = [16, 7, 20, 21,
     29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2, 8, 24, 14,
     32, 27, 3, 9,
     19, 13, 30, 6,
     22, 11, 4, 25]

S = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
[0, 15, 7 , 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
[4, 1, 14, 8, 13, 6, 2, 11 ,15 ,12, 9, 7, 3, 10, 5, 0],
[15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]]

,[[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
[3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
[0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
[13, 8, 10, 1, 3, 15, 4, 2 ,11, 6, 7, 12, 0, 5, 14, 9]]

,[[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
[13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
[13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
[1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]]

,[[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
[13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
[10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
[3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]]

,[[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
[14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9 , 8, 6],
[4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
[11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]]

,[[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
[10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
[9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
[4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6 , 0, 8, 13]]

,[[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
[13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
[1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
[6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]]

,[[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
[1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
[7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
[2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

def rol(number, value):
    return ((number << value) & 0xFFFFFFF) | (number >> (28 - value))
def ror(number, value):
    return (number >> value ) | ((number << (28 - value)) & 0xFFFFFFF)
def parityCalc(key):
    pKey = 0
    #print(bin(key))
    for i in range(8):
        b = (key & (0x7F << (57 - (i * 7)))) >> (57 - (i * 7))
        count = 0
     #   print(bin(b))
        for j in range(8):
            if(b & (1 << j)):
                count += 1
        if(count % 2 == 0):
            pKey = (pKey << 8) | ((b << 1) | 0x01)
        else:
            pKey = (pKey << 8) | (b << 1)
        #print(bin(pKey))
    return pKey

#calculate key schedule from input key
def keySchedule(key, encrypt = True):
    shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2 ,2, 2, 2, 1]
    PC1 = [57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
           10, 2, 59, 51, 43, 35, 27,
           19, 11, 3, 60, 52, 44, 36,
           63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
           14, 6, 61, 53, 45, 37, 29,
           21, 13, 5, 28, 20, 12, 4]
    PC2 = [14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32]
    TC = 0
    TD = 0
    for i in range(28): 
        TC = (TC << 1) | ((key & (1 << (64 - PC1[i]))) >> (64 - PC1[i]))
    for i in range(28, 56):
        TD = (TD << 1) | ((key & (1 << (64 - PC1[i]))) >> (64 - PC1[i]))
    K = [0 for x in range(16)]
    if encrypt == True:
        for i in range(16):
            TC = rol(TC, shifts[i])
            TD = rol(TD, shifts[i])
            CD = (TC << 28) | TD
            for j in range(48):
                K[i] = (K[i] << 1) | ((CD & (1 << (56 - PC2[j]))) >> (56 - PC2[j]))
    else:
        shifts = [0, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2 ,2, 2, 2, 1]
        for i in range(16):
            TC = ror(TC, shifts[i])
            TD = ror(TD, shifts[i])
            CD = (TC << 28) | TD
            for j in range(48):
                K[i] = (K[i] << 1) | ((CD & (1 << (56 - PC2[j]))) >> (56 - PC2[j]))
    return K

def encryptBlock(msg, keys: list):
    return processBlock(processBlock(processBlock(msg, keys[0], True), keys[1], False), keys[2], True)
def decryptBlock(msg, keys: list):
    return processBlock(processBlock(processBlock(msg, keys[2], False), keys[1], True), keys[0], False)

def processBlock(msg, key, encrypt = True):
    #compute parity bits
    #pKey = parityCalc(key)
    K = keySchedule(key, encrypt)
    LR = 0
    #initial permutation
    for i in IP:
        LR = (LR << 1) | ((msg & (1 << (64 - i))) >> (64 - i))
    #split result into 32 bit halves
    L0 = (LR & 0xFFFFFFFF00000000) >> 32
    R0 = LR & 0xFFFFFFFF
    tempL = L0
    tempR = R0
    L = tempL
    R = tempR
    for i in range(16):
        T = 0
        tempL = L
        L = tempR
        for e in E:
            T = (T << 1) | ((tempR & (1 << (32 - e))) >> (32 - e))
        T1 = T ^ K[i]
        T2 = 0
        for j in range(8):
            b = (T1 & (0b111111 << (42 - j * 6))) >> (42 - j * 6)
            r = 2 * ((b & 0b100000) >> 5) + (b & 1)
            c = (b & 0b011110) >> 1
            T2 = (T2 << 4) | S[j][r][c]
        T3 = 0
        for p in P:
            T3 = (T3 << 1) |((T2 & (1 << (32 - p))) >> (32 - p))
        
        R = tempL ^ T3
        tempR = R
    L = (R << 32) | L
    C = 0
    for i in invIP:
        C = (C << 1) | (L & (1 << (64 - i))) >> (64 - i)
    return C

def CFBEncrypt(msg: bytes, keys: list, IV = 0, pgpMode = True):
    #set feedback register to Initialization Vector which is 0
    feedbackRegister = 0
    #l = ceil(len(msg)/8)
    msgFromBytes = []
    #convert input into 64 bit blocks
    for i in range(len(msg)):
        toAppend = (int).from_bytes(msg[i * 8: (i + 1) * 8], "big")
        if len(msg[i*8:(i+1)*8]) == 0:
            break
        msgFromBytes.append(toAppend)
    if pgpMode == True:

        #each entry of the list holds a single octet
        cipherBlocks = [0 for i in range(len(msg)+10)]
        randomPrefix = secrets.randbits(64)
        #repeat last two octets of random data
        randomPrefix = (randomPrefix << 16) | (randomPrefix & 0xFFFF) 
        #print(hex(randomPrefix))
        #encrypt FR to produce FRE (encryption of all-zero value)
        feedbackRegisterEncrypted = encryptBlock(feedbackRegister, keys)
        #XOR FRE with first 8 octets of random data producing first 8 octets of ciphertext
        feedbackRegisterEncrypted = feedbackRegisterEncrypted ^ ((randomPrefix & 0xFFFFFFFFFFFFFFFF0000) >> 16)
        feedbackRegister = 0
        for i in range(8):
            cipherBlocks[i] = (feedbackRegisterEncrypted & (0xFF << (56 - i * 8))) >> (56 - i * 8)
            #print(hex(cipherBlocks[i]))
            feedbackRegister |= (cipherBlocks[i] << (56 - i * 8))

        feedbackRegisterEncrypted = encryptBlock(feedbackRegister, keys)
        repeatedOctets = ((feedbackRegisterEncrypted & (0xFFFF << 48))>>48) ^ (randomPrefix & 0xFFFF)
        #print(hex(randomPrefix & 0xFFFF))
        #cipherBlocks[8] = ((feedbackRegisterEncrypted & (0xFF << 56) >> 56) ^ (randomPrefix & (0xFFFF))) >> 8 
        #cipherBlocks[9] = ((feedbackRegisterEncrypted & (0xFF << 48) >> 48) ^ (randomPrefix & 0xFF)) 
        cipherBlocks[8] = (repeatedOctets & 0xFF00) >> 8
        cipherBlocks[9] = repeatedOctets & 0xFF

        feedbackRegister = 0
        for i in range(8):
            feedbackRegister |= (cipherBlocks[i+2] << (56 - i * 8))
        feedbackRegisterEncrypted = encryptBlock(feedbackRegister, keys)
        #print(hex(msgFromBytes[0]))
        feedbackRegisterEncrypted ^= msgFromBytes[0]
        for i in range(8):
            cipherBlocks[i+10] = (feedbackRegisterEncrypted & (0xFF << (56 - i * 8))) >> (56 - i * 8)
        feedbackRegister = 0

        if len(msgFromBytes) > 1:
            for j in range(8):
                feedbackRegister |= (cipherBlocks[10+j] << (56 - j * 8))
            feedbackRegisterEncrypted = encryptBlock(feedbackRegister, keys)
            feedbackRegisterEncrypted ^= msgFromBytes[1]
            for j in range(8):
                cipherBlocks[j+18] = (feedbackRegisterEncrypted & (0xFF << (56 - j * 8))) >> (56 - j * 8)
            for i in range(len(msgFromBytes)-2):
                feedbackRegister = 0
                for j in range(8):
                    feedbackRegister |= (cipherBlocks[(8*i+18) + j] << (56 - j * 8))
                feedbackRegisterEncrypted = encryptBlock(feedbackRegister, keys)
                feedbackRegisterEncrypted ^= msgFromBytes[i + 2]
                for j in range(8):
                    cipherBlocks[8*(i+1) + 18 + j] = (feedbackRegisterEncrypted & (0xFF << (56 - j * 8))) >> (56 - j * 8)
    else:
        cipherBlocks = [0 for i in range(len(msg))]
        feedbackRegisterEncrypted = encryptBlock(IV, keys)
        feedbackRegisterEncrypted = feedbackRegisterEncrypted ^ msgFromBytes[0]
        for i in range(8):
            cipherBlocks[i] = (feedbackRegisterEncrypted & (0xFF << (56 - i * 8))) >> (56 - i * 8)
        for i in range(len(msgFromBytes)-1):
            feedbackRegister = feedbackRegisterEncrypted
            feedbackRegisterEncrypted = encryptBlock(feedbackRegister, keys)
            feedbackRegisterEncrypted ^= msgFromBytes[i+1]
            for j in range(8):
                cipherBlocks[8*(i+1) + j] = (feedbackRegisterEncrypted & (0xFF << (56 - j * 8))) >> (56 - j * 8)
    return cipherBlocks

def CFBDecrypt(msg: bytes, keys: list, IV = 0, pgpMode = True):
    if pgpMode == True:
        l = len(msg)
        msgFromBytes = []
        toAppend = (int).from_bytes(msg[0:8], "big")
        msgFromBytes.append(toAppend)
        toAppend = (int).from_bytes(msg[8 : 10], "big")
        msgFromBytes.append(toAppend)
        for i in range(ceil(len(msg)/8)-2):
            toAppend = (int).from_bytes(msg[i * 8 + 10: (i + 1) * 8 + 10 ], "big")
            if len(msg[i*8:(i+1)*8]) == 0:
                break
            msgFromBytes.append(toAppend)
        cipherBlocks = [0 for i in range(l)]
        
        feedbackRegister = 0
        feedbackRegisterEncrypted = encryptBlock(feedbackRegister, keys)
        feedbackRegisterEncrypted ^= msgFromBytes[0]
        for j in range(8):
            cipherBlocks[j] = (feedbackRegisterEncrypted & (0xFF << (56 - j * 8))) >> (56 - j * 8)
        feedbackRegister = msgFromBytes[0]
        feedbackRegisterEncrypted = encryptBlock(feedbackRegister, keys)
        cipherBlocks[8] = ((feedbackRegisterEncrypted & (0xFF << 56) ) ^ (msgFromBytes[1] << 48)) >> 56
        cipherBlocks[9] = (((feedbackRegisterEncrypted & (0xFF << 48) ) ^ (msgFromBytes[1] << 48)) >> 48) & 0xFF
        
        feedbackRegister = 0
        feedbackRegister = (msgFromBytes[0] & 0xFFFFFFFFFFFF)
        feedbackRegister = (feedbackRegister << 16) | msgFromBytes[1] 
        feedbackRegisterEncrypted = encryptBlock(feedbackRegister, keys)
        feedbackRegisterEncrypted ^= msgFromBytes[2]
        for i in range(8):
            cipherBlocks[i+10] = (feedbackRegisterEncrypted & (0xFF << (56 - i * 8))) >> (56 - i * 8)
        if len(msgFromBytes) > 3:
            feedbackRegister = msgFromBytes[2]
            
            for i in range(len(msgFromBytes)-3):
                feedbackRegisterEncrypted = encryptBlock(feedbackRegister, keys)
                feedbackRegisterEncrypted ^= msgFromBytes[i+3]
                for j in range(8):
                    cipherBlocks[8 * i + j + 18 ] = (feedbackRegisterEncrypted & (0xFF << (56 - j * 8))) >> (56 - j * 8)
                feedbackRegister = msgFromBytes[i+3]
    else:
        feedbackRegister = 0
        msgFromBytes = []
        #convert input into 64 bit blocks
        for i in range(len(msg)):
            toAppend = (int).from_bytes(msg[i * 8: (i + 1) * 8], "big")
            if len(msg[i*8:(i+1)*8]) == 0:
                break
            msgFromBytes.append(toAppend)
        cipherBlocks = [0 for i in range(len(msg))]
        feedbackRegisterEncrypted = encryptBlock(IV, keys)
        feedbackRegisterEncrypted = feedbackRegisterEncrypted ^ msgFromBytes[0]
        for i in range(8):
            cipherBlocks[i] = (feedbackRegisterEncrypted & (0xFF << (56 - i * 8))) >> (56 - i * 8)
        for i in range(len(msgFromBytes)-1):
            feedbackRegister = msgFromBytes[i]
            feedbackRegisterEncrypted = encryptBlock(feedbackRegister, keys)
            feedbackRegisterEncrypted ^= msgFromBytes[i+1]
            for j in range(8):
                cipherBlocks[8*(i+1) + j] = (feedbackRegisterEncrypted & (0xFF << (56 - j * 8))) >> (56 - j * 8)
    return cipherBlocks
    

