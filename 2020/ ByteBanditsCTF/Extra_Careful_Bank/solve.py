from pwnapi import *

transactions = []

log.level = 2

p = remote("crypto.byteband.it", 7003)

def transfer(receiverid, amount):
	p.sendlineafter(b":\n", b"1")
	p.sendlineafter(b":\n", str(receiverid).encode("utf-8"))
	p.sendlineafter(b":\n", str(amount).encode("utf-8"))

def gettransactions():
	p.sendlineafter(b":\n", b"2")
	return [(x[:32], x[32:64], x[64:96]) for x in [p.recvline().strip().decode("utf-8") for i in range(20)]]

def getspecialtransaction():
	p.sendlineafter(b":\n", b"3")
	p.recvline()
	line = p.recvline().strip().decode("utf-8")
	return (line[:32], line[32:64], line[64:96])

def sendencryptedtransactions(transactions, special):
	p.sendlineafter(b":\n", b"4")

	stats = {}

	for t in transactions:
		if t[2] not in stats:
			stats[t[2]] = []
		stats[t[2]].append((t[0], t[1]))

		if len(stats[t[2]]) == 10:
			myid, mytransactions = t[0], stats[t[2]]
			break

	victims = list(set([t[1] for t in mytransactions]))

	for i in range(3):
		p.sendlineafter(b":\n", "{}{}{}".format(victims[i], myid, special[2]).encode("utf-8"))

	p.recvline()

def getflag():
	p.sendlineafter(b":\n", b"5")
	return p.recvline()

log.info("Executing 10 transactions")
transfer(1, 1)
transfer(1, 1)
transfer(1, 1)
transfer(2, 1)
transfer(2, 1)
transfer(2, 1)
transfer(3, 1)
transfer(3, 1)
transfer(3, 1)
transfer(3, 1)

log.info("Retrieving transactions executed today")
transactions = gettransactions()

log.info("Retrieving special transaction")
special = getspecialtransaction()

log.info("Sending crafted transactions")
sendencryptedtransactions(transactions, special)

log.info("Retrieving flag")
flag = getflag()

log.info(flag.strip().decode("utf-8"))
p.close()