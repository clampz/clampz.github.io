---
layout: post
title: "swap"
---

# swap - tokyo westerns ctf 3rd 2017

The swapping is interesting. Let's try!

nc pwn1.chal.ctf.westerns.tokyo 19937
[swap](https://twctf2017.azureedge.net/attachments/swap-b878cc5ecf612cee902acdc91054486bb4cb3bb337a0cfbaf903ba8d35cfcd17)
[libc.so.6](https://twctf2017.azureedge.net/attachments/libc.so.6-4cd1a422a9aafcdcb1931ac8c47336384554727f57a02c59806053a4693f1c71)

this is a post-mortem writeup i worked on the problem during the ctf but did not solve it in time. i read [this solution](https://github.com/xerosec/CTFs/blob/master/tw2017/swap.py) and wrote my own exploit.

it looks like that we can actually attempt swap values at any given location in memory. :boom: how cool, this is like demolition in a binary form.

```
$ checksec swap
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$ nc pwn1.chal.ctf.westerns.tokyo 19937 
<pause>
==============================================
1. Set addrsses
2. Swap both addrress of value
0. Exit
Your choice:
1
Please input 1st addr
0xffffff
Please input 2nd addr
0xfefefe
==============================================
1. Set addrsses
2. Swap both addrress of value
0. Exit
Your choice:
2
<exit>
```

we're given a 64bit binary! i checked the memory map and readelf to see which addresses were static & readable/writable we know ASLR is enabled.

## memory map
```
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /home/toorconctf/ctf/clampz/tokyowestern/swap/swap
0x0000000000600000 0x0000000000601000 0x0000000000000000 r-- /home/toorconctf/ctf/clampz/tokyowestern/swap/swap
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /home/toorconctf/ctf/clampz/tokyowestern/swap/swap
0x00007fe0bf4e8000 0x00007fe0bf6a6000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/libc-2.19.so
0x00007fe0bf6a6000 0x00007fe0bf8a6000 0x00000000001be000 --- /lib/x86_64-linux-gnu/libc-2.19.so
0x00007fe0bf8a6000 0x00007fe0bf8aa000 0x00000000001be000 r-- /lib/x86_64-linux-gnu/libc-2.19.so
0x00007fe0bf8aa000 0x00007fe0bf8ac000 0x00000000001c2000 rw- /lib/x86_64-linux-gnu/libc-2.19.so
0x00007fe0bf8ac000 0x00007fe0bf8b1000 0x0000000000000000 rw-
0x00007fe0bf8b1000 0x00007fe0bf8d4000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/ld-2.19.so
0x00007fe0bfac2000 0x00007fe0bfac5000 0x0000000000000000 rw-
0x00007fe0bfad1000 0x00007fe0bfad3000 0x0000000000000000 rw-
0x00007fe0bfad3000 0x00007fe0bfad4000 0x0000000000022000 r-- /lib/x86_64-linux-gnu/ld-2.19.so
0x00007fe0bfad4000 0x00007fe0bfad5000 0x0000000000023000 rw- /lib/x86_64-linux-gnu/ld-2.19.so
0x00007fe0bfad5000 0x00007fe0bfad6000 0x0000000000000000 rw-
0x00007ffc040ae000 0x00007ffc040c3000 0x0000000000000000 rw- [stack]
0x00007ffc04178000 0x00007ffc0417a000 0x0000000000000000 r-x [vdso]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 r-x [vsyscall]
gef➤  dereference 0x0000000000601000 50
0x0000000000601000│+0x00: 0x0000000000600e28  →  0x0000000000000001
0x0000000000601008│+0x08: 0x00007fe0bfad51c8  →  0x0000000000000000
0x0000000000601010│+0x10: 0x00007fe0bf8c7670  →  0x2404894838ec8348
0x0000000000601018│+0x18: 0x00007fe0bf557d60  →  0xe85355fc89495441
0x0000000000601020│+0x20: 0x00000000004006c6  →  0xffd0e90000000168
0x0000000000601028│+0x28: 0x00007fe0bf5d7320  →  0x7500002d8d4d3d83
0x0000000000601030│+0x30: 0x00007fe0bf509e50  →  0x4855544155415641
0x0000000000601038│+0x38: 0x00000000004006f6  →  0xffa0e90000000468
0x0000000000601040│+0x40: 0x0000000000400706  →  0xff90e90000000568
0x0000000000601048│+0x48: 0x00007fe0bf5585a0  →  0x894855f289495441
```

## relocations table
```
Relocation section '.rela.dyn' at offset 0x530 contains 4 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000600ff8  000600000006 R_X86_64_GLOB_DAT 0000000000000000 __gmon_start__ + 0
000000601080  000c00000005 R_X86_64_COPY     0000000000601080 stdout@GLIBC_2.2.5 + 0
000000601090  000d00000005 R_X86_64_COPY     0000000000601090 stdin@GLIBC_2.2.5 + 0
0000006010a0  000e00000005 R_X86_64_COPY     00000000006010a0 stderr@GLIBC_2.2.5 + 0
Relocation section '.rela.plt' at offset 0x590 contains 10 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000601018  000100000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
000000601020  000200000007 R_X86_64_JUMP_SLO 0000000000000000 __stack_chk_fail@GLIBC_2.4 + 0
000000601028  000300000007 R_X86_64_JUMP_SLO 0000000000000000 read@GLIBC_2.2.5 + 0
000000601030  000400000007 R_X86_64_JUMP_SLO 0000000000000000 __libc_start_main@GLIBC_2.2.5 + 0
000000601038  000500000007 R_X86_64_JUMP_SLO 0000000000000000 atoll@GLIBC_2.2.5 + 0
000000601040  000700000007 R_X86_64_JUMP_SLO 0000000000000000 memcpy@GLIBC_2.14 + 0
000000601048  000800000007 R_X86_64_JUMP_SLO 0000000000000000 setvbuf@GLIBC_2.2.5 + 0
000000601050  000900000007 R_X86_64_JUMP_SLO 0000000000000000 atoi@GLIBC_2.2.5 + 0
000000601058  000a00000007 R_X86_64_JUMP_SLO 0000000000000000 exit@GLIBC_2.2.5 + 0
000000601060  000b00000007 R_X86_64_JUMP_SLO 0000000000000000 sleep@GLIBC_2.2.5 + 0
----- # took this info to gdb:
gef➤  x/xg 0x601028
0x601028:       0x00007f4b79dc7220    <--- read
gef➤  x/xg 0x601040
0x601040:       0x0000000000400706    <--- memcpy
gef➤  p/d 0x601028
$1 = 6295592        <--- read
gef➤  p/d 0x601040
$2 = 6295616        <--- memcpy
```

  we also need to know which addresses effect control of execution, we know the stack does but its randomized. the relocations section effects execution, this includes both the global offset table and the program linkage table. and they're both at static addresses without the program independant executable (PIE) protection. one thing i noticed that i felt was of note is that memcpy and exit have static addresses in their got entries. the rest of the entries in the got seem like randomized addresses:

```
0x0000000000601028│+0x28: 0x00007fc4ba412220  →  0x7fc4ba412220  <read+0>  cmp DWORD PTR [rip+0x2d2519], 0x0        # 0x7fc4ba6e4740
0x0000000000601030│+0x30: 0x00007fc4ba33b740  →  0x7fc4ba33b740  <__libc_start_main+0>  push r14         ← $rax, $rsi
0x0000000000601038│+0x38: 0x00007fc4ba351eb0  →  0x7fc4ba351eb0  <atoll+0>  mov edx, 0xa
0x0000000000601040│+0x40: 0x0000000000400706  →  0xff90e90000000568
0x0000000000601048│+0x48: 0x00007fc4ba38ae70  →  0x7fc4ba38ae70  <setvbuf+0>  push rbp
0x0000000000601050│+0x50: 0x00007fc4ba351e80  →  0x7fc4ba351e80  <atoi+0>  sub rsp, 0x8
0x0000000000601058│+0x58: 0x0000000000400736  →  0xff60e90000000868
0x0000000000601060│+0x60: 0x00007fc4ba3e7230  →  0x7fc4ba3e7230  <sleep+0>  push rbp
0x0000000000601068│+0x68: 0x00
0x0000000000601070│+0x70: 0x00
0x0000000000601078│+0x78: 0x00
0x0000000000601080│+0x80: 0x00007fc4ba6e0620  →  0xfbad2887
0x0000000000601088│+0x88: 0x00
0x0000000000601090│+0x90: 0x00007fc4ba6df8e0  →  0xfbad208b
0x0000000000601098│+0x98: 0x00
0x00000000006010a0│+0xa0: 0x00007fc4ba6e0540  →  0xfbad2087
0x00000000006010a8│+0xa8: 0x00
0x00000000006010b0│+0xb0: 0x00
0x00000000006010b8│+0xb8: 0x00
0x00000000006010c0│+0xc0: 0x00
0x00000000006010c8│+0xc8: 0x00
0x00000000006010d0│+0xd0: 0x00
0x00000000006010d8│+0xd8: 0x00
0x00000000006010e0│+0xe0: 0x00
0x00000000006010e8│+0xe8: 0x00
gef➤  p puts
$1 = {<text variable, no debug info>} 0x7fc4ba38a690 <puts>
gef➤  x/2xw &puts
0x7fc4ba38a690 <puts>:  0x49555441      0xe853fc89
gef➤  x/2xw 0x004006b0
0x4006b0 <puts@plt>:    0x096225ff      0x00680020
gef➤  p/x 0x0000000000601028
$2 = 0x601028
gef➤  p/x 0x4006b0
$3 = 0x4006b0
gef➤  p/d $2
$4 = 6295592
gef➤  p/d $3
$5 = 4196016
gef➤ 
```

