import tripleDES

keys = [
    0x0123456789abcdef,
    0x23456789abcdef01,
    0x456789abcdef0123
]
IV = 0xf69f2445df4f9b17

plaintext = 0x6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51
out = tripleDES.CFBEncrypt(plaintext.to_bytes(32, "big"), keys, IV)
ciphertext = 0x078BB74E59CE7ED67666DE9CF95EAF3FE9ED6BB460F451528A5F9FE4ED710918 
y = 0
for i in range(len(out)):
    y = (y << 8) | out[i]
print(hex(y))
print(hex(ciphertext))
print(y == ciphertext)

out = tripleDES.CFBDecrypt(y.to_bytes(32, "big"), keys, IV)
y = 0
for i in range(len(out)):
    y = (y << 8) | out[i]
print(hex(y))
print(hex(plaintext))
print(y == plaintext)