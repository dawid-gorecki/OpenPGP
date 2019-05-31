#ElGamal.py
#Implementation of ElGamal public-key encryption scheme

from .auxiliary import *
import secrets

def OctetsToInteger(oct):
    l = len(oct)
    x = 0
    for i in range(l):
        x += oct[i] * 256**(l - 1 - i)
    return x


def Encrypt(msg, p, g, y, k=0):
    m = msg
    while(k == 0):
        k = secrets.randbelow(p-2)
    gamma = squareAndMultiply(g, k, p)
    delta = (m * squareAndMultiply(y, k, p)) % p
    return (gamma, delta)

def Decrypt(msg, p, x):
    pre = squareAndMultiply(msg[0], p-1-x, p)
    return (pre * msg[1]) % p
