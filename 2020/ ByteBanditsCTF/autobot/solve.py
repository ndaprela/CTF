import angr, base64, r2pipe, sys
from pwnapi import *

log.level = 2

def findTargets(name):
	r = r2pipe.open(name)

	good = None
	bad = None

	for s in r.cmdj("izj"):	
		if "good" in s["string"].lower():
			good = s["vaddr"]
		if "wrong" in s["string"].lower():
			bad = s["vaddr"]

	if good == None or bad == None:
		print("STRINGS NOT FOUND")

	r.cmd("aaa")
	find = [x["from"]+0x400000 for x in r.cmdj("axtj @{}".format(good))]
	avoid = [x["from"]+0x400000 for x in r.cmdj("axtj @{}".format(bad))]
	r.quit()

	return find, avoid

def symbolicExecution(name, find, avoid):
	project = angr.Project(name)
	initial_state = project.factory.entry_state()
	simulation = project.factory.simgr(initial_state)
	simulation.explore(find=find, avoid=avoid)

	if simulation.found:
		solution_state = simulation.found[0]
		return solution_state.posix.dumps(sys.stdin.fileno())
	else:
		raise Exception('Could not find the solution')

p = remote("pwn.byteband.it", 6000)
i = 0

while True:

	name = "out"+str(i)

	with open(name, "wb") as f:
		f.write(base64.b64decode(p.recvline().strip()))

	find, avoid = findTargets(name)
	sol = symbolicExecution(name, find, avoid)

	p.sendline(sol)
	i += 1

p.close()
