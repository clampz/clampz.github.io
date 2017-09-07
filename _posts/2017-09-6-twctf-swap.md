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

  i had to think through what would happen by replacing memcpy with read, there are three calls to read but the second one is where we've got the most control. assuming we enter "0" for the first input and some destination write address for the second input; the first call would result in a non-fatal error which there are no checks for since our destination buffer would be null, the second call would result in our intended write, and the third call would also result in a non-fatal error. so the plan would be to swap memcpy for read since they take the same type arguments and then we have an arbitrary write primitive. with that we can overwrite atoi, looking at read_int:

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

  we must however consider that after overwriting atoi we potentially cripple our menu because atoi returned the menu option selected. we can however keep our write primitive in tact by abusing the return value of puts, examine the return of puts when we leak mem.


