from random import seed, randint
from time import time
from pwn import *

def bruteSeed(numbers):
	i = i0 = int(time.time())-5000

	while i - i0 < 10000:
		seed(i)
		numbers2 = [randint(5, 10000) for _ in range(10)]
		if numbers == numbers2:
			log.info("Seed found: {}".format(i))
			return i
		i += 1

	return -1
# j = int
# u = j.to_bytes
# s = 73
# t = 479105856333166071017569
# _ = 1952540788
# s = 7696249
# o = 6648417
# m = 29113321535923570
# e = 199504783476
# _ = 7827278
# r = 435778514803
# a = 6645876
# n = 157708668092092650711139
# d = 2191175
# o = 2191175
# m = 7956567
# _ = 6648417
# m = 7696249
# e = 465675318387
# s = 4568741745925383538
# s = 2191175
# a = 1936287828
# g = 1953393000
# e = 29545

# g = b"rgbCTF{REDACTED}"

p = remote("challenge.rgbsec.xyz", 12345)

p.recvline()

numbers = [int(p.recvline()) for _ in range(10)]

p.recvuntil(": ")
enc = int(p.recvline())

log.info(numbers)
log.info(enc)

s = bruteSeed(numbers)
seed(s)
_ = [randint(5, 10000) for _ in range(10)]

b = bytearray([randint(0, 255) for _ in range(40)])

g = int.to_bytes(enc, 1024, "little")

log.info("Flag: {}".format("".join([chr(l ^ p) for l, p in zip(g, b)])))

# n = int.from_bytes(bytearray([l ^ p for l, p in zip(g, b)]), 'little')
# print("Here's another number I found: ", n)

p.close()

"""
[+] Opening connection to challenge.rgbsec.xyz on port 12345: Done
[*] [5959, 9997, 6277, 3105, 9371, 5942, 5858, 4810, 43, 6230]
[*] 26577721120464114923767816984797598060885428790014249068390566711912
[*] Seed found: 1595234953
[*] Flag: rgbCTF{random_is_not_secure}\x05ý­j¤@\x1f|£\x1a
[*] Closed connection to challenge.rgbsec.xyz port 12345
"""
