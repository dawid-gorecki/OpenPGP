#DSA.py
#implementation of the Digital Signature Algorithm
import aux
from SHA512 import Hash
import secrets
#this enum determines the four choices of bit lengths of p and q which may be used



def Sign(M ,p, q, g, x, N, k = 0):
    outlen = 512
    if k == 0:
        k = secrets.randbelow(q)
    kInv = aux.modularInverse(k, q)
    r = 0
    s = 0
    while(s == 0 or r == 0):
        r = aux.squareAndMultiply(g, k, p) % q
        z = Hash(M) >> (outlen - N)
        s = (kInv * (z + x * r )) % q
    return r, s




def Verify(M, p, q, g, r, s, y, N):
    outlen = 512
    if( 0 < r < q and 0 < s < q):
        w = aux.modularInverse(s, q)
        z = Hash(M) >> (outlen - N)
        u1 = z*w % q
        u2 = r*w % q
        v = (aux.squareAndMultiply(g, u1, p) * aux.squareAndMultiply(y, u2, p) % p) % q
        if(r == v):
            return True
    return False

    
