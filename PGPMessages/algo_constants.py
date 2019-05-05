from enum import Enum

class PublicKeyAlgo(Enum):
    RSA_ENCRYPT_OR_SIGN = 1
    RSA_ENCRYPT_ONLY = 2
    RSA_SIGN_ONLY = 3
    ELGAMAL_ENCRYPT_ONLY = 16
    DSA = 17
    RESERVED_ELLIPTIC_CURVE = 18
    RESERVED_ECDSA = 19
    RESERVED = 20
    RESERVED_DIFFIE_HELLMAN = 21

class SymKeyAlgo(Enum):
    PLAINTEXT_OR_UNENCRYPTED_DATA = 0
    IDEA = 1
    TRIPLE_DES = 2
    CAST5 = 3
    BLOWFISH = 4
    AES_128 = 7
    AES_192 = 8
    AES_256 = 9
    TWOFISH_256 = 10

class CompressionAlgo(Enum):
    UNCOMPRESSED = 0
    ZIP = 1 
    ZLIB = 2
    BZIP2 = 3

class HashAlgo(Enum):
    MD5 = 1
    SHA1 = 2
    RIPE_MD160 = 3
    SHA256 = 8
    SHA384 = 9
    SHA512 = 10
    SHA224 = 11