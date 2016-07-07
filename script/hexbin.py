#!/usr/bin/env python3
import sys

v=str()
f=open(sys.argv[2], 'wb')
string=str()

for i in sys.argv[1].strip():
    v = v + i
    if len(v) == 2:
        v.encode("ascii")
        h = int(str(v), base=16)
        f.write(chr(h).encode("ISO-8859-1"))
        v = str()
