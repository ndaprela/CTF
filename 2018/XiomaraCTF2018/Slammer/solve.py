#!/usr/bin/env python3
import r2pipe

r = r2pipe.open("./slammer")
r.cmd("ood 2>/dev/null")
r.cmd("s 0x0060016d")

print("FLAG: ", end="", flush=True)
while True:
    rax = r.cmdj("pdj 1")[0]["ptr"]
    print(chr(rax), end="", flush=True)
    if rax == 0x7d: # '}'
        print()
        break
    r.cmd("dr rax="+str(rax))
    rip = r.cmdj("pdj 2")[1]["jump"]+3
    r.cmd("dr rip="+str(rip))
    r.cmd("s rip")
    edi = r.cmdj("pdj 1")[0]["ptr"]
    r.cmd("ds " + str(5*edi+4))
    r.cmd("s rip")
    r.cmd("so +1")
