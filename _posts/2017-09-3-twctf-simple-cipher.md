---
layout: post
title: "simple cipher"
---

# my simple cipher - tokyo westerns ctf 3rd 2017

This my first cipher system. Can you break it?
[my-simple-cipher.7z](https://twctf2017.azureedge.net/attachments/my-simple-cipher.7z-bb72c6605237320dfaf8eb3459e8806d27ceb73f118224ec3acbf5f77aa836d1)

```
cat encrypted.txt                  
7c153a474b6a2d3f7d3f7328703e6c2d243a083e2e773c45547748667c1511333f4f745e

cat cipher.py             
#!/usr/bin/python2                     

import sys                             
import random                          

key = sys.argv[1]                      
flag = '**CENSORED**'                  

assert len(key) == 13                  
assert max([ord(char) for char in key]) < 128                                  
assert max([ord(char) for char in flag]) < 128                                 

message = flag + "|" + key             

encrypted = chr(random.randint(0, 128))                                        

for i in range(0, len(message)):       
  encrypted += chr((ord(message[i]) + ord(key[i % len(key)]) + ord(encrypted[i])) % 128)                                                                       

print(encrypted.encode('hex'))
```

did simple math to find the first few chars of the string and now im having to guess for the rest because the only thing i know is the first random char of 'encrypted' and the flag starts with TWCTF{

recovering the first few characters of the key:

```
>>> first_char = chr(0x7c)
>>> next_char = chr(0x15)
>>> flag = 'TWCTF{'
>>> key = ''
>>> (ord(flag[0]) + 00 + ord(first_char)) % 128
80
>>> ord(next_char)
21
>>> (ord(flag[0]) + 50 + ord(first_char)) % 128
2
>>> (ord(flag[0]) + 70 + ord(first_char)) % 128
22
>>> (ord(flag[0]) + 71 + ord(first_char)) % 128
23
>>> (ord(flag[0]) + 69 + ord(first_char)) % 128
21
```

these are the possible options for the first character of the flag:

```
[*] key: ENJ0YHO flag = TWCTF{C
[*] key: ENJ0YHI flag = TWCTF{I
[*] key: ENJ0YHE flag = TWCTF{M
[*] key: ENJ0YHA flag = TWCTF{Q
[*] key: ENJ0YH8 flag = TWCTF{Z
```

but i think these are the most likely:

```
[*] key: ENJ0YHO flag = TWCTF{C
    * [*] key: ENJ0YHOL flag = TWCTF{Cr
        * [*] key: ENJ0YHOLI flag = TWCTF{Cry
    * [*] key: ENJ0YHOR flag = TWCTF{Cl
[*] key: ENJ0YHI flag = TWCTF{I
[*] key: ENJ0YHE flag = TWCTF{M
    * [*] key: ENJ0YHEL flag = TWCTF{Mr
    * [*] key: ENJ0YHEE flag = TWCTF{My
```

once i did some experimenting i thought about what the rest of the key could be seeing as its only 13 characters:

```
key: ENJ0YHOLIDAY flag = TWCTF{Crypto
```

but what about the final character? here are our options:

```
[*] key: ENJ0YHOLIDAY~ flag = TWCTF{CryptoP
[*] key: ENJ0YHOLIDAY} flag = TWCTF{CryptoQ
[*] key: ENJ0YHOLIDAY| flag = TWCTF{CryptoR
[*] key: ENJ0YHOLIDAY{ flag = TWCTF{CryptoS
[*] key: ENJ0YHOLIDAY` flag = TWCTF{Crypton
[*] key: ENJ0YHOLIDAY_ flag = TWCTF{Cryptoo
[*] key: ENJ0YHOLIDAY^ flag = TWCTF{Cryptop
[*] key: ENJ0YHOLIDAY] flag = TWCTF{Cryptoq
[*] key: ENJ0YHOLIDAY\ flag = TWCTF{Cryptor
[*] key: ENJ0YHOLIDAY[ flag = TWCTF{Cryptos
[*] key: ENJ0YHOLIDAYZ flag = TWCTF{Cryptot
[*] key: ENJ0YHOLIDAYY flag = TWCTF{Cryptou
[*] key: ENJ0YHOLIDAYX flag = TWCTF{Cryptov
[*] key: ENJ0YHOLIDAYW flag = TWCTF{Cryptow
[*] key: ENJ0YHOLIDAYV flag = TWCTF{Cryptox
[*] key: ENJ0YHOLIDAYU flag = TWCTF{Cryptoy
[*] key: ENJ0YHOLIDAYT flag = TWCTF{Cryptoz
[*] key: ENJ0YHOLIDAY- flag = TWCTF{Crypto!
[*] key: ENJ0YHOLIDAY, flag = TWCTF{Crypto"
[*] key: ENJ0YHOLIDAY+ flag = TWCTF{Crypto#
[*] key: ENJ0YHOLIDAY* flag = TWCTF{Crypto$
[*] key: ENJ0YHOLIDAY) flag = TWCTF{Crypto%
[*] key: ENJ0YHOLIDAY( flag = TWCTF{Crypto&
[*] key: ENJ0YHOLIDAY' flag = TWCTF{Crypto'
[*] key: ENJ0YHOLIDAY& flag = TWCTF{Crypto(
[*] key: ENJ0YHOLIDAY% flag = TWCTF{Crypto)
[*] key: ENJ0YHOLIDAY$ flag = TWCTF{Crypto*
[*] key: ENJ0YHOLIDAY# flag = TWCTF{Crypto+
[*] key: ENJ0YHOLIDAY" flag = TWCTF{Crypto,
[*] key: ENJ0YHOLIDAY! flag = TWCTF{Crypto-
[*] key: ENJ0YHOLIDAYS flag = TWCTF{Crypto{
[*] key: ENJ0YHOLIDAYR flag = TWCTF{Crypto|
[*] key: ENJ0YHOLIDAYQ flag = TWCTF{Crypto}
[*] key: ENJ0YHOLIDAYP flag = TWCTF{Crypto~
```

and of those i think the most likely ones are:

```
[*] key: ENJ0YHOLIDAY~ flag = TWCTF{CryptoP
[*] key: ENJ0YHOLIDAYZ flag = TWCTF{Cryptot
[*] key: ENJ0YHOLIDAY$ flag = TWCTF{Crypto*
[*] key: ENJ0YHOLIDAY! flag = TWCTF{Crypto-
```

after considering those options i was able to recover the rest this way:

```
>>> flag = 'TWCTF{Crypto-'
>>> key = 'ENJ0YHOLIDAY!'
>>> for i in range(13, 35):
  2     for flag_char in flag_likely_chars:
  3         if ( ( (ord(flag_char) + ord(key[i % len(key)]) + ord(encrypted[i])) % 128 ) == ord(encrypted[i+1]) ):
  4             print("[{}]".format(str(i)) + "flag currently is: {}".format(flag + flag_char))
  5             x = raw_input("continue? (y/n): ")
  6             if (x == 'y'):
  7                 flag += flag_char
  8                 continue
[13]flag currently is: TWCTF{Crypto-i
continue? (y/n): y
[14]flag currently is: TWCTF{Crypto-is
continue? (y/n): y
[15]flag currently is: TWCTF{Crypto-is-
continue? (y/n): y
[16]flag currently is: TWCTF{Crypto-is-f
continue? (y/n): y
[17]flag currently is: TWCTF{Crypto-is-fu
continue? (y/n): y
[18]flag currently is: TWCTF{Crypto-is-fun
continue? (y/n): y
[19]flag currently is: TWCTF{Crypto-is-fun!
continue? (y/n): y
[20]flag currently is: TWCTF{Crypto-is-fun!}
continue? (y/n): y
[21]flag currently is: TWCTF{Crypto-is-fun!}|
continue? (y/n): y
[22]flag currently is: TWCTF{Crypto-is-fun!}|E
continue? (y/n): y
[23]flag currently is: TWCTF{Crypto-is-fun!}|EN
continue? (y/n): y
[24]flag currently is: TWCTF{Crypto-is-fun!}|ENJ
continue? (y/n): y
[25]flag currently is: TWCTF{Crypto-is-fun!}|ENJ0
continue? (y/n): y
[26]flag currently is: TWCTF{Crypto-is-fun!}|ENJ0Y
continue? (y/n): y
[27]flag currently is: TWCTF{Crypto-is-fun!}|ENJ0YH
continue? (y/n): y
[28]flag currently is: TWCTF{Crypto-is-fun!}|ENJ0YHO
continue? (y/n): y
[29]flag currently is: TWCTF{Crypto-is-fun!}|ENJ0YHOL
continue? (y/n): y
[30]flag currently is: TWCTF{Crypto-is-fun!}|ENJ0YHOLI
continue? (y/n): y
[31]flag currently is: TWCTF{Crypto-is-fun!}|ENJ0YHOLID
continue? (y/n): y
[32]flag currently is: TWCTF{Crypto-is-fun!}|ENJ0YHOLIDA
continue? (y/n): y
[33]flag currently is: TWCTF{Crypto-is-fun!}|ENJ0YHOLIDAY
continue? (y/n): y
[34]flag currently is: TWCTF{Crypto-is-fun!}|ENJ0YHOLIDAY!
continue? (y/n): y
```

i wrote a small script to verify the answer's correctness too:

```
cat verify-key.py   
#!/usr/bin/python2

import sys
import random

key = 'ENJ0YHOLIDAY!'
flag ='TWCTF{Crypto-is-fun!}'

assert len(key) == 13
assert max([ord(char) for char in key]) < 128
assert max([ord(char) for char in flag]) < 128

message = flag + "|" + key

encrypted = '|'
#encrypted = chr(random.randint(0, 128))

for i in range(0, len(message)):
  encrypted += chr((ord(message[i]) + ord(key[i % len(key)]) + ord(encrypted[i])) % 128)

print(message)
print(repr(encrypted))
print(repr("7c153a474b6a2d3f7d3f7328703e6c2d243a083e2e773c45547748667c1511333f4f745e".decode('hex')))
```

it produces output like below:

```
~/ctf/clampz/tokyowestern/simple_cipher
./verify-key.py  
TWCTF{Crypto-is-fun!}|ENJ0YHOLIDAY!
'|\x15:GKj-?}?s(p>l-$:\x08>.w<ETwHf|\x15\x113?Ot^'
'|\x15:GKj-?}?s(p>l-$:\x08>.w<ETwHf|\x15\x113?Ot^'
```
