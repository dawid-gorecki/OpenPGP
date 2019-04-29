#SHA.py
#SHA-512 implementation
#The only function from this file that should be used externally is Hash


import sys
import math
#circular right shift
#this function assumes 64 bit values
def ror(value, amount):
    #basically copy of the C idiom for bit rotation in simplified form
    #we can do this because rotation amounts are known to be not greater than 64 bits
    return  (value >> amount) | (value << (64 - amount))
#the following six functions are operations defined by the specification
#for SHA-512 
def Ch(x, y, z):
    return (x & y)^(~x & z)
def Maj(x, y, z):
    return (x & y)^(x & z)^(y & z)
def sigmaZero(x):
    return ror(x, 28) ^ ror(x, 34) ^ ror(x, 39)
def sigmaOne(x):
    return ror(x, 14) ^ ror(x, 18) ^ ror(x, 41)
def deltaZero(x):
    return (ror(x, 1) ^ ror(x, 8) ^ (x >> 7))
def deltaOne(x):
    return (ror(x, 19) ^ ror(x, 61) ^ (x >> 6))

#Calculate a SHA-512 hash of the input bytes or byterray object
def Hash(msg):

    #initialize hash values
    #these initial values are defined as the first sixty-four bits of the
    #fractional parts of the square roots of the first eight prime numbers
    H = [0x6a09e667f3bcc908,
         0xbb67ae8584caa73b,
         0x3c6ef372fe94f82b,
         0xa54ff53a5f1d36f1, 
         0x510e527fade682d1, 
         0x9b05688c2b3e6c1f, 
         0x1f83d9abfb41bd6b, 
         0x5be0cd19137e2179]

    #initialize round constants:
    #first 64 bits of the fractional parts of the cube roots of the first 80 primes
    k = [     0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
              0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
              0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
              0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
              0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
              0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
              0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
              0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
              0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
              0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
              0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
              0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
              0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
              0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
              0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
              0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817]
    #Preprocessing
    #First step: padding
    #convert 
    #append 1 to the end of the message
    modulus64 = 2 ** 64

    pre = int.from_bytes(msg, "big")
    l = len(msg) * 8
    pre = (pre << 1) | 1
    #calculate amount of zeros to append including room for 128-bit representation of l
    zeros = 896 - 1 - l % 1024
    if zeros < 0:
        zeros += 1024
    pre = pre << zeros + 128
    #append l to the temporary variable pre
    pre |= l
    #parsing the message
    #if bit_length is smaller than this value we need to explicitly add zero bits
    N = math.ceil(pre.bit_length()/1024)
    if pre.bit_length() < 1023:
        msg = msg + pre.to_bytes(math.ceil(pre.bit_length()/8), "big")
        N = math.ceil(len(msg*8)/1024)
    else:
    #the message including padding will be parsed into N 1024-bit blocks
        msg = pre.to_bytes(N * 128 , "big")

    #convert the padded data to a bytes object
    #split each 1024-bit block into 16 64-bit words
    #not sure which way of writing the assignment to N looks neater, left one commented out
    M = [[0 for x in range(16)]for y in range(N)]
    for i in range(N):
        for j in range(16):
            #M[N - i - 1][j] = (pre >> ((1024 - 64 * (j + 1)) + 1024 * i)) & 0xFFFFFFFFFFFFFFFF
            M[i][j] = int.from_bytes(msg[8 * j + i * 128: 8 * (j+1) + i * 128], "big") & 0xFFFFFFFFFFFFFFFF
    W = [0 for x in range(80)]
    for i in range(N):
        for t in range(16):
            W[t] = M[i][t]
        for t in range(16, 80):
            W[t] = (deltaOne(W[t-2]) + W[t-7] + deltaZero(W[t-15]) + W[t-16]) % modulus64     
        a = H[0]
        b = H[1]
        c = H[2]
        d = H[3]
        e = H[4]
        f = H[5]
        g = H[6]
        h = H[7]
        for t in range(80):
            TempVar1 = (h + sigmaOne(e) + Ch(e, f, g) + k[t] + W[t]) % (modulus64)
            TempVar2 = (sigmaZero(a) + Maj(a, b, c)) % (modulus64)
            h = g
            g = f
            f = e
            e = (d + TempVar1) % (modulus64)
            d = c
            c = b
            b = a
            a = (TempVar1 + TempVar2) % (modulus64)

        H[0] = (a + H[0]) % modulus64
        H[1] = (b + H[1]) % modulus64
        H[2] = (c + H[2]) % modulus64
        H[3] = (d + H[3]) % modulus64
        H[4] = (e + H[4]) % modulus64
        H[5] = (f + H[5]) % modulus64
        H[6] = (g + H[6]) % modulus64
        H[7] = (h + H[7]) % modulus64

    #concatenate words and return result
    result = H[0]
    for i in range(7):
        result = result << 64 | H[i+1]
    return result
