#! /usr/bin/python3

import SHA512

testVal = 0xce044bc9fd43269d5bbc946cbebc3bb711341115cc4abdf2edbc3ff2c57ad4b15deb699bda257fea5aef9c6e55fcf4cf9dc25a8c3ce25f2efe90908379bff7ed 

x = SHA512.Hash(bytes('Z'*0x2000000, "UTF-8"))

# if x == testVal:
    # print("Ok")