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
    """Encrypt(msg, p, g, y, k) -> (gamma, delta)
        Encrypt msg using ElGamal public key encryption.\n
        P and g are key parameters which are generated during the key generation process 
        and y is the public key of the recipient. K is a randomly generated single-use key.
        Returns 2-tuple representing encrypted message.
    """
    m = msg
    while(k == 0):
        k = secrets.randbelow(p-2)
    gamma = squareAndMultiply(g, k, p)
    delta = (m * squareAndMultiply(y, k, p)) % p
    return (gamma, delta)

def Decrypt(msg, p, x):
    """Decrypt msg in the form of a 2-tuple containing output of ElGamal encryption using 
        the prime p generated during key generation and the recipient's private key.\n
        Returns integer representing decrypted message.
    """
    pre = squareAndMultiply(msg[0], p-1-x, p)
    return (pre * msg[1]) % p
