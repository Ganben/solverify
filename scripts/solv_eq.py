#!/usr/bin/python
from z3 import *


x = Real('x')
y = Real('y')
z = Real('z')
s = Solver()
s.add(3*x + 2*y - z == 1)
s.add(2*x - 2*y + 4*z == -2)
s.add(-x + 0.5*y - z == 0)
print s.check()
print s.model()



circle, square, triangle = Ints('circle square triangle')
s = Solver()
s.add(circle+circle==10)
s.add(circle*square+square==12)
s.add(circle*square-triangle*circle==circle)
print s.check()
print s.model()

out = BitVec('out', 64)
tmp=[]
for i in range(64):
    tmp.append((out>>i)&0x3F)
s=Solver()
# all overlapping 6-bit chunks must be distinct:
s.add(Distinct(*tmp))
# MSB must be zero:
s.add((out&0x8000000000000000)==0)
print s.check()
result=s.model()[out].as_long()
print "0x%x" % result
# print overlapping 6-bit chunks:
for i in range(64):
    t=(result>>i)&0x3F
    print " "*(63-i) + format(t, 'b').zfill(6)