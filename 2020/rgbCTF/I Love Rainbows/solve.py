import string, hashlib

def md5(s):
	m=hashlib.md5()
	m.update(s)
	return m.hexdigest()

def sha256(s):
	m=hashlib.sha256()
	m.update(s)
	return m.hexdigest()

db={}

for c in string.printable:
	db[md5(c.encode("utf-8"))] = c
	db[sha256(c.encode("utf-8"))] = c
	for d in string.printable:
		db[md5((c+d).encode("utf-8"))] = c+d
		db[sha256((c+d).encode("utf-8"))] = c+d

with open("rainbows.txt", "r") as f:
	lines = f.read().split()

for p in lines:
	print(db[p], end="") # rgbCTF{4lw4ys_us3_s4lt_wh3n_h4shing}
