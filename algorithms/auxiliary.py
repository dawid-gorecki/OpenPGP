#aux.py
#library of auxiliary functions for encryption algorithms


import secrets
import sys
import math
from enum import Enum
smallPrimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
oddPrimes = [3, 5, 7, 11, 13, 17, 19, 23, 29]
class number(Enum):
    probablyPrime = True
    Composite = False


#def modularMultiplication(a, b, mod):

def sessionKeyChecksum(key):
    if type(key) != int:
        raise TypeError('Session key must be an integer')
    if key.bit_length() > 192:
        raise ValueError('Session key too long')
    checksum = 0
    for i in range(24):
        checksum += (key & (0xFF << i * 8)) % 65536
    return checksum     

def modularInverse(z, a):
    if(a > 0 and z > 0 and z < a):
        i = a
        j = z
        y2 = 0
        y1 = 1
        while(j > 0):
            quotient = i//j
            remainder = i - ( j * quotient)
            y = y2 - (y1 * quotient)
            i = j
            j = remainder
            y2 = y1
            y1 = y
        if(i != 1):
            raise ValueError
    else:
        raise ValueError('z or a are not positve or z is greater or equal to a')
    return y2 % a
#returns a**k modulo n
def squareAndMultiply(a, k, n):
    """squareAndMultiply(a, k, n) -> a**k % n

        Calculates a**k % n more efficiently
    """
    b = 1
    if k == 0:
        return b
    if k >= n:
        raise ValueError('exponent k must be smaller than modulus n')
    kBin = k.to_bytes( math.ceil(k.bit_length()/8), 'big')
    klen = len(kBin)
    A = a
    if kBin[klen - 1] & 0x01 == 0x01:
        b = a
    for j in range(1, 8):
        A = (A ** 2) % n
        if (kBin[klen - 1] & (1 << j) == (1 << j)):
            b = A * b % n     
    for i in range(1, klen):
        for j in range(8):
            A = (A ** 2) % n
            if (kBin[klen - i - 1] & (1 << j) == (1 << j)):
                b = A * b % n
    return b


def millerRabin(w, iterations):# algorithm 4.24 HAC 
    w = math.floor(w)
    v = w - 1
    a = 1
    while(v % (2 ** ( a + 1)) == 0):
        a += 1

    m = math.floor((w - 1) / 2**a)

    try:
        for i in range(iterations):
            b = secrets.randbelow(w-2)
            while(b <= 1 or b > (w - 2)):
                b = secrets.randbelow(w-2)
            #z = squareAndMultiply(b, m, w)
            z = b ** m % w
            if(z == w - 1 or z == 1):
                continue
            for j in range(a - 1):
                #z = squareAndMultiply(z, 2, w)
                z = z ** 2 % w
                if(z == w - 1):
                    break
                elif(z == 1):
                    return number.Composite
            if(z != w  - 1):
                return number.Composite
        return number.probablyPrime
    except ZeroDivisionError:
        print("z = " + str(z) + " b = " + str(b) + " m = " + str(m))
        sys.exit()



def randomSearch(nbits, iterations):  #algorithm 4.44
    while(True):
        n = secrets.randbits(nbits)
        while n % 2 == 0 or n < 3:
            n = secrets.randbits(nbits)
        isDivisibleByPrime = False
        for i in oddPrimes:
            if n % i == 0:
                isDivisibleByPrime = True
                break
        if isDivisibleByPrime == True:
            continue
        if millerRabin(n, iterations) == number.probablyPrime:
            return n
        

def totient(n): #calculate Euler's phi function
    phi = n
    f = factor(n)
    for p in f:
        if f[p] > 0 and p != 1:
            phi *= (1 - 1/p)
    return round(phi)


def factor(n):
    factors = {}
    for i in smallPrimes:
        factors[i] = 0
    for i in smallPrimes:
        while(n % i == 0):
            factors[i] += 1
            n /= round(i)
    factors[n] = 1 
    return factors
