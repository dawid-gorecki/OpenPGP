#DSA.py
#implementation of the Digital Signature Algorithm
from .auxiliary import *
from .SHA512 import Hash
import secrets
#this enum determines the four choices of bit lengths of p and q which may be used



def Sign(M ,p, q, g, x, N, k = 0):
    """Sign calculates the signature of M using DSA and SHA-512 where M
        is an integer.\n
        P,q and g are parameters created during key generation, while
        x is the signer's private key and N is the bit length of q.
        K is the randomly generated per-user key.\n
        The output of Sign is a 2-tuple representing the signature.    
    """
    outlen = 512
    if k == 0:
        k = secrets.randbelow(q)
    kInv = modularInverse(k, q)
    r = 0
    s = 0
    while(s == 0 or r == 0):
        r = squareAndMultiply(g, k, p) % q
        z = Hash(M) >> (outlen - N)
        s = (kInv * (z + x * r )) % q
    return r, s




def Verify(M, p, q, g, r, s, y, N):
    """Verify signature (r,s) of message M using key parameters p, q and g
    and the sender's public key y. N is bit length of prime q.\n
    Function returns True if message was verified successfully and False on failure.    
    """
    outlen = 512
    if( 0 < r < q and 0 < s < q):
        w = modularInverse(s, q)
        z = Hash(M) >> (outlen - N)
        u1 = z*w % q
        u2 = r*w % q
        v = (squareAndMultiply(g, u1, p) * squareAndMultiply(y, u2, p) % p) % q
        if(r == v):
            return True
    return False

    
