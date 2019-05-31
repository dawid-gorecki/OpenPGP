import os, sys
path = os.path.abspath(os.getcwd())
sys.path.append(path)
file_path = path
if os.name == 'nt':
    file_path += '\\algorithms\\tests\\elgamal_test_vectors.csv'
elif os.name == 'posix':
    file_path += '/algorithms/tests/elgamal_test_vectors.csv'
#test vectors are taken from
#https://gist.github.com/devinrsmith/58926b3d62ccfe9818057f94d2c7189c#file-elgamal_test_vectors-csv
from algorithms.ElGamal import *
from algorithms.auxiliary import *
file = open(file_path)
count = 1
for line in file:
    vals = line.split(',')
    if vals[0] == 'p':
        continue
    p = int(vals[0])
    g = int(vals[1])
    x = int(vals[2])
    k = int(vals[3])
    m = int(vals[4])
    a = int(vals[5])
    b = int(vals[6])
    y = squareAndMultiply(g, x, p)
    ciphertext = Encrypt(m, p, g, y, k)
    if ciphertext == (a, b):
        print("test " + str(count) + " passed")
    count += 1
