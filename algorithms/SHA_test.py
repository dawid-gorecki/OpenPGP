#! /usr/bin/python3

from .SHA512 import *
import cProfile
import io
import pstats
import tracemalloc
from pstats import SortKey
tracemalloc.start()
testVal = 0xce044bc9fd43269d5bbc946cbebc3bb711341115cc4abdf2edbc3ff2c57ad4b15deb699bda257fea5aef9c6e55fcf4cf9dc25a8c3ce25f2efe90908379bff7ed 
pr = cProfile.Profile()
pr.enable()
#tracemalloc.start()
#0x20000000
x = Hash(bytearray('Z'*10000000, "UTF-8"))
#snapshot = tracemalloc.take_snapshot()
#top_stats = snapshot.statistics('lineno')

#for stat in top_stats[:15]:
 #   print(stat)
pr.disable()
s = io.StringIO()
sortby = SortKey.CUMULATIVE
ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
ps.print_stats()
print(s.getvalue())
if x == testVal:
    print("Ok")