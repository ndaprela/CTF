# Slammer

For this challenge we are given a file called `slammer`, let's check what it might be using
the `file` command.

```
$ file ./slammer 
./slammer: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
```
Now that we know what it is we can try to run it.

```
$ ./slammer 
password: acab
Wrong!
```
We are asked for a password, we enter some random stuff and after a few seconds we are
presented with a `Wrong!` message.

We can try to use `strace` to have a more detailed insight about what's going on during
execution.

```
$ strace ./slammer 
execve("./slammer", ["./slammer"], 0x7ffda1af2100 /* 24 vars */) = 0
write(1, "password: \0", 11password: ) = 11
read(0, acab"acab\n", 50) = 5
nanosleep({tv_sec=3, tv_nsec=0}, NULL) = 0
write(1, "Wrong!\n\0", 8Wrong!) = 8
exit(1) = ?
+++ exited with 1 +++
```

Not much, at least we discovered the reason behind the pause before the message.

# Reversing

If we open the file with IDA it complains about the SHT size or offset being fucked up
though it still works. Instead gdb complains about the file format not being correct, without working.
We could probably fix these things but why not just use radare?
So let's open the file with radare.

```
$ r2 ./slammer
-- In Soviet Russia, radare2 has documentation.
[0x00600120]> 
```

We begin by checking the sections of the binary.

```asm
[0x00600120]> iS
[Sections]
00 0x00000000 278 0x00400000 278 m-r-- LOAD0
01 0x00000120 3400 0x00600120 3400 m-rwx LOAD1
02 0x00000000 0 0x00000000 0 m-rw- GNU_STACK
03 0x00000000 64 0x00400000 64 m-rw- ehdr
```

The `LOAD1` section is both writable and executable...maybe we have some polymorphic
code?

Let's have a look at the strings in the binary, maybe the flag is just right there (we haven't
tried a simple `strings` yet), who knows?

```asm
[0x00600120]> iz
[0x00600120]> izz
000 0x000000e8 0x004000e8 10 11 (LOAD0) ascii password: 
001 0x000000f3 0x004000f3 7 8 (LOAD0) ascii Wrong!\n
002 0x000000fb 0x004000fb 10 11 (LOAD0) ascii Good job!\n
[...]
```

`iz` returns no strings since it searches only in the data sections, on the other hand `izz`
finds two familiar strings and a new interesting one `"Good job!\n"` besides other useless
stuff, at least for our purposes.

Let's see if we can find any cross-reference to `"Good job!\n"` and possibly how to reach that part of code.

```asm
[0x00600120]> aa
[x] Analyze all flags starting with sym. and entry0 (aa)
[0x00600120]> axt 0x4000fb
[0x00600120]> 
```

No luck for us, the string doesn't seem to be referenced anywhere in the code, but we had
the suspect that this could be self modifying code, didn't we?

Let's have a look at the disassembly of our program.

```asm
[0x00600120]> pd 32
;-- section.LOAD1:
;-- rip:
/ (fcn) entry0 347
| entry0 (int arg_19h, int arg_7e7e3e7eh);
| ; arg int arg_19h @ rbp+0x19
| ; arg int arg_7e7e3e7eh @ rbp+0x7e7e3e7e
| 0x00600120 b801000000 mov eax, 1
| 0x00600125 bf01000000 mov edi, 1
| 0x0060012a 48bee8004000. movabs rsi, 0x4000e8
| 0x00600134 ba0b000000 mov edx, 0xb
| 0x00600139 0f05 syscall
| 0x0060013b 4881ec000100. sub rsp, 0x100
| 0x00600142 b800000000 mov eax, 0
| 0x00600147 bf00000000 mov edi, 0
| 0x0060014c 4889e6 mov rsi, rsp
| 0x0060014f ba32000000 mov edx, 0x32
| 0x00600154 0f05 syscall
| 0x00600156 b823000000 mov eax, 0x23
| 0x0060015b bf06014000 mov edi, 0x400106
| 0x00600160 31f6 xor esi, esi
| 0x00600162 0f05 syscall
| 0x00600164 4889e1 mov rcx, rsp
| 0x00600167 48ffc9 dec rcx
| 0x0060016a 48ffc1 inc rcx
| 0x0060016d 803978 cmp byte [rcx], 0x78
| ,=< 0x00600170 7427 je 0x600199| | 0x00600172 b801000000 mov eax, 1
| | 0x00600177 bf01000000 mov edi, 1
| | 0x0060017c 48bef3004000. movabs rsi, 0x4000f3
| | 0x00600186 ba08000000 mov edx, 8
| | 0x0060018b 0f05 syscall
| | 0x0060018d b83c000000 mov eax, 0x3c
| | 0x00600192 bf01000000 mov edi, 1
| | 0x00600197 0f05 syscall
| `-> 0x00600199 488b01 mov rax, qword [rcx]
| 0x0060019c bfb60c0000 mov edi, 0xcb6
| 0x006001a1 31f6 xor esi, esi
| 0x006001a3 39fe cmp esi, edi
```

As we previously saw with `strace` we have three system calls being called: `write`,
`read`, `nanosleep`.

After that a pointer to our string in the stack is copied in to `rcx`.

The first byte is then compared with `0x78` which is the ascii code for `x`, if it's different
the `exit` system call is executed otherwise we jump to `0x600199`, so let's see what we
have there.

```asm
[0x00600120]> pd 10 @ 0x600199
| 0x00600199 488b01 mov rax, qword [rcx]
| 0x0060019c bfb60c0000 mov edi, 0xcb6
| 0x006001a1 31f6 xor esi, esi
| .-> 0x006001a3 39fe cmp esi, edi
| ,==< 0x006001a5 740b je 0x6001b2
| |: 0x006001a7 673086b20160. xor byte [esi + 0x6001b2], al
| |: 0x006001ae ffc6 inc esi
| |`=< 0x006001b0 ebf1 jmp 0x6001a3
| `--> 0x006001b2 3087b9f84111 xor byte [rdi + 0x1141f8b9], al
| 0x006001b8 0c5f or al, 0x5f
```

It is a loop which xors a region of memory with the first character of the string we supplied
as input and after the loop jumps at the xored memory.

Let's try to debug the program (remember gdb couldn't do that?) to let it decrypt itself.

We reopen the file in debug mode.

```asm
[0x00600120]> ood
Process with PID 748 started...
File dbg:///home/vagrant/shared/slammer/slammer reopened in read-write 
mode = attach 748 748 748
```

Since we had some issues with`dcu` command we will instead use `ds`.

```asm
[0x00600120]> dr rax=0x78
0x00000000 ->0x00000078
[0x00600120]> dr rip=0x60019c
0x00600120 ->0x0060019c
[0x0060019c]> ds 16274
[0x0060019c]> s rip
```

With the previous instructions we first initialize`rax` to `0x78`, we then move the
instruction pointer to the decryption loop and we execute 16274 instructions `(5*0xcb6+4)`.

Now we can seek to the instruction pointer and see what the code looks like after
decryption.

```asm
[0x0060019c]> s rip
[0x006001b2]> pd 20
;-- rip:
0x006001b2 48ffc1 inc rcx
0x006001b5 803969 cmp byte [rcx], 0x69
,=< 0x006001b8 7427 je 0x6001e1
| 0x006001ba b801000000 mov eax, 1
| 0x006001bf bf01000000 mov edi, 1
| 0x006001c4 48bef3004000. movabs rsi, 0x4000f3
| 0x006001ce ba08000000 mov edx, 8
| 0x006001d3 0f05 syscall
| 0x006001d5 b83c000000 mov eax, 0x3c
| 0x006001da bf01000000 mov edi, 1
| 0x006001df 0f05 syscall
`-> 0x006001e1 488b01 mov rax, qword [rcx]
0x006001e4 bf6e0c0000 mov edi, 0xc6e
0x006001e9 31f6 xor esi, esi
.-> 0x006001eb 39fe cmp esi, edi,==< 0x006001ed 740b je 0x6001fa
|: 0x006001ef 673086fa0160. xor byte [esi + 0x6001fa], al
|: 0x006001f6 ffc6 inc esi
|`=< 0x006001f8 ebf1 jmp 0x6001eb
`--> 0x006001fa 2196a8e95006 and dword [rsi + 0x650e9a8], edx
```

We have the same structure as in the first iteration but with different numbers like`0x69`
which is `i` and a different size of the region to xor.

The scenario in now clear: the program checks a char from the password, if it is correct it
decrypts the next part of code and jumps to it repeating this process until a wrong char or
the end is reached.

We just need to automate things. We're gonna use r2pipe.

This is our script.

```python
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
```

At every iteration we read the desired value from the`cmp` instruction and print it, since it is the next character of our flag. If we have still not reached the end we set `rax` to that value, we then extract the address of the decryption loop and set `rip` to that address+3 (we skip the first instruction that initializes `rax`) and we finally iterate through the loop and update the seek pointer to the next `cmp`.

```
$ ./solve_slammer.py 
FLAG: xiomara{cool_thumbs_up_if_solved_using_r2pipe}
```

That's all for this possible solution of the challenge. It could be solved in other ways doing
less reversing, for example with `pintools` (link [here](https://ctftime.org/writeup/8861) for a
writeup using that option)
