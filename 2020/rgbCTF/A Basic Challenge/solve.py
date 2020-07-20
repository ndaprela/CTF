import base64

with open("basic_chall.txt") as f:
	tokens = f.read().split()

print("".join(map(lambda t: chr(int(t, 8)), base64.b64decode(("".join(map(lambda h: chr(int(h, 16)), "".join(map(lambda t: chr(t), map(lambda t: int(t, 2), tokens))).split())).encode("utf-8"))).split())))
# rgbCTF{c0ngr4ts_0n_b3ing_B4SIC}
