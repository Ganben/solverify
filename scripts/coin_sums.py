# -*- encoding=utf8 -*-
# ganben copy

from z3 import *

a,b,c,d,e,f,g,h = Ints('a b c d e f g h')
s =Solver()

s.add(1*a+2*b+5*c+10*d+20*e+50*f+100*g + 200*h == 200,
      a>=0, b>=0, c>=0,d>=0,e>=0,f>=0,g>=0,h>=0)
result = []

while True:
    if s.check() == sat:
        m = s.model()
        print(m)
        result.append(m)

        block = []
        for d in m:
            if d.arity() > 0:
                raise Z3Exception("uninterpretend functions are not supported")
            c=d()
            if is_array(c) or c.sort().kind() == Z3_UNINTERPRETED_SORT:
                raise Z3Exception("array and uninterpreted sorts are not supported")
            block.append(c !=m[d])
        s.add(Or(block))
    else:
        print(len(result))
        break
