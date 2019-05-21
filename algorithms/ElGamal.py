#ElGamal.py
#Implementation of ElGamal public-key encryption scheme

import aux
import secrets

def OctetsToInteger(oct):
    l = len(oct)
    x = 0
    for i in range(l):
        x += oct[i] * 256**(l - 1 - i)
    return x


def Encrypt(msg, p, g, y, k):
    m = msg
    while(k == 0):
        k = secrets.randbelow(p-2)
    gamma = aux.squareAndMultiply(g, k, p)
    delta = (m * aux.squareAndMultiply(y, k, p)) % p
    return (gamma, delta)

def Decrypt(msg, p, x):
    pre = aux.squareAndMultiply(msg[0], p-1-x, p)
    return (pre * msg[1]) % p
