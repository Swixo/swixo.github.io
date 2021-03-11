---
title: "HackTheBox - Enterprise"
description: Walkthrough de la machine Enterprise sur HackTheBox
---
![enterprise](https://i.imgur.com/I3wDQWo.png)

Bonjour à tous, aujourd'hui je vous présente une machine notée hard qui est vraiment intéréssante pour les débutants en **exploitation** de **binaire** et en **Docker container escapes** : **Enterprise** de **HackTheBox**. 😃

# Recon

## Nmap 

[...]

# Vertical Privilege Escalation

Après une légère énumération, nous trouvons un binaire suid pas commum :

![suid](https://i.imgur.com/BMkUGO3.png)

Le programme nous demande un code d'accès... Commençons par effectuer un ltrace pour en savoir plus.

[ltrace](https://github.com/dkogan/ltrace) est un outil qui permet d'intercepter les appels dynamiques de librairie ainsi que les appels systèmes d'un processus.

![ltrace](https://i.imgur.com/pS4hmx1.png)

Ici nous pouvons voir que le programme appel la fonction **strcmp**, cette fonction compare 2 chaines de caratères. En l'occurence ici, il compare notre string entrée grace à la fonction fgets, avec le véritable code d'accès qui est picarda1.
Cependant après connexion, le programme nous affiche seulement un menu principal.

Nous comprenons donc que nous allons devoir exploiter une vulnérabilité de notre binaire afin d'élever nos privilèges. Cependant la fonction **fgets** vérifie le buffer / la taille de notre saisie.

Nous pouvons transférer l'executable pour utiliser [gdb-peda](https://github.com/longld/peda) sur notre machine :

![transfert_binary](https://i.imgur.com/6uD2jeP.png)

Tout d'abord vérifions les proctections que contient ce binaire ainsi que l'ASLR sur la machine cible:

```sh
ON MY MACHINE :
  ❯ checksec --file=$PWD/lcars.bin
  [*] '/home/nuts/Documents/Hack_The_Box/Enterprise/lcars.bin'
      Arch:     i386-32-little
      RELRO:    Partial RELRO
      Stack:    No canary found
      NX:       NX disabled
      PIE:      PIE enabled
      RWX:      Has RWX segments
ON TARGET MACHINE:
  www-data@enterprise:/bin$ cat /proc/sys/kernel/randomize_va_space
  0
```

L'ASLR est donc désactivé car sa valeur vaut 0 et non 2. Deplus NX 

Je vais alors debugger le programme afin de comprendre son fonctionnement :




