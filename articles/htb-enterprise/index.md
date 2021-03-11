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

Après une légère énumération, nous trouvons un binaire SUID pas commum :

![suid](https://i.imgur.com/BMkUGO3.png)

SUID est un type spécial de permissions données à un fichier. Normalement, lorsqu'un programme s'exécute, il hérite des autorisations d'accès de l'utilisateur connecté. SUID est défini comme donnant des permissions temporaires à un utilisateur pour exécuter un programme/fichier avec les permissions du propriétaire du fichier plutôt que de l'utilisateur qui l'exécute.

Le programme nous demande un code d'accès... Commençons par effectuer un ltrace pour en savoir plus.

[ltrace](https://github.com/dkogan/ltrace) est un outil qui permet d'intercepter les appels dynamiques de librairie ainsi que les appels systèmes d'un processus.

![ltrace](https://i.imgur.com/pS4hmx1.png)

Ici nous pouvons voir que le programme appel la fonction **strcmp**, cette fonction compare 2 chaines de caratères. En l'occurence ici, il compare notre string entrée grace à la fonction fgets, avec le véritable code d'accès qui est picarda1.
Cependant après connexion, le programme nous affiche seulement un menu principal.

Nous comprenons donc que nous allons devoir exploiter une vulnérabilité dans notre binaire afin d'élever nos privilèges. Cependant la fonction **fgets** vérifie le buffer / la taille de notre saisie.

Nous pouvons transférer l'exécutable sur notre machine pour utiliser [gdb-peda](https://github.com/longld/peda) :

![transfert_binary](https://i.imgur.com/6uD2jeP.png)

Tout d'abord vérifions les protections applicatives que contient ce binaire ainsi que l'[ASLR](https://www.networkworld.com/article/3331199/what-does-aslr-do-for-linux.html) sur la machine cible:

```sh
ON MY MACHINE :
  ❯ checksec --file=$PWD/lcars.bin  # Check properties
  [*] '/home/nuts/Documents/Hack_The_Box/Enterprise/lcars.bin'
      Arch:     i386-32-little
      RELRO:    Partial RELRO
      Stack:    No canary found
      NX:       NX disabled
      PIE:      PIE enabled
      RWX:      Has RWX segments
      
ON TARGET MACHINE:
  www-data@enterprise:/bin$ cat /proc/sys/kernel/randomize_va_space # Check ASLR
  0
```

L'ASLR est donc désactivé car sa valeur vaut 0 et non 2. Deplus NX n'est pas activé.

`L’address space layout randomization (ASLR) est une technique permettant de placer de façon aléatoire les zones de données dans la mémoire virtuelle.`

`NX est une protection qui rend la pile Non eXécutable.`

Je vais alors debugger le programme afin de comprendre son fonctionnement.

Après plusieurs minutes, j'ai trouvé un buffer overflow :

![segfault](https://i.imgur.com/bII4f6j.png)

Nous avons réussi à faire **segmentation fault** le programme grace à une saisie trop importante dans une variable non initialisée avec un buffer inférieur à la saisie car la fonction d'input ne vérifie pas la taille de notre chaine de caractères. 😁

Grâce à un buffer overflow, nous pouvons reécrire la sauvegarde EIP. (Instruction Pointer Register) Le registre EIP contient toujours l'adresse de la prochaine instruction à exécuter.

![bof_schema](https://i.imgur.com/UIh4wUo.png)

Pour cela il faut trouver le bon padding afin de overwrite convenablement nos registres (4 octets en 32 bits) et d'exécuter un shell en tant que root car je rappel que le binaire est SUID sur la machine.

Pour calculer ce padding nous allons voir 2 solutions :

### 1st solution

```assembly
gdb-peda$ disassemble main_menu 
Dump of assembler code for function main_menu:
   0x0000085e <+0>:	push   ebp
   0x0000085f <+1>:	mov    ebp,esp
   0x00000861 <+3>:	push   ebx
   0x00000862 <+4>:	sub    esp,0x1a4
   0x00000868 <+10>:	call   0x620 <__x86.get_pc_thunk.bx>
   0x0000086d <+15>:	add    ebx,0x2793
   0x00000873 <+21>:	mov    DWORD PTR [ebp-0xd4],0x0
   0x0000087d <+31>:	call   0x750 <startScreen>
   0x00000882 <+36>:	sub    esp,0xc
   0x00000885 <+39>:	lea    eax,[ebx-0x2113]
   0x0000088b <+45>:	push   eax
   0x0000088c <+46>:	call   0x590 <puts@plt>
   0x00000891 <+51>:	add    esp,0x10
   0x00000894 <+54>:	sub    esp,0xc
   0x00000897 <+57>:	lea    eax,[ebx-0x2110]
   0x0000089d <+63>:	push   eax
   0x0000089e <+64>:	call   0x590 <puts@plt>
   0x000008a3 <+69>:	add    esp,0x10
   0x000008a6 <+72>:	sub    esp,0xc
   0x000008a9 <+75>:	lea    eax,[ebx-0x20e0]
   0x000008af <+81>:	push   eax
   0x000008b0 <+82>:	call   0x590 <puts@plt>
   0x000008b5 <+87>:	add    esp,0x10
   0x000008b8 <+90>:	sub    esp,0xc
   0x000008bb <+93>:	lea    eax,[ebx-0x20d2]
   0x000008c1 <+99>:	push   eax
   0x000008c2 <+100>:	call   0x590 <puts@plt>
   0x000008c7 <+105>:	add    esp,0x10
   0x000008ca <+108>:	sub    esp,0xc
   0x000008cd <+111>:	lea    eax,[ebx-0x20c5]
   0x000008d3 <+117>:	push   eax
   0x000008d4 <+118>:	call   0x590 <puts@plt>
   0x000008d9 <+123>:	add    esp,0x10
   0x000008dc <+126>:	sub    esp,0xc
   0x000008df <+129>:	lea    eax,[ebx-0x20ba]
   0x000008e5 <+135>:	push   eax
   0x000008e6 <+136>:	call   0x590 <puts@plt>
   0x000008eb <+141>:	add    esp,0x10
   0x000008ee <+144>:	sub    esp,0xc
   0x000008f1 <+147>:	lea    eax,[ebx-0x20ae]
   0x000008f7 <+153>:	push   eax
   0x000008f8 <+154>:	call   0x590 <puts@plt>
   0x000008fd <+159>:	add    esp,0x10
   0x00000900 <+162>:	sub    esp,0xc
   0x00000903 <+165>:	lea    eax,[ebx-0x2099]
   0x00000909 <+171>:	push   eax
   0x0000090a <+172>:	call   0x590 <puts@plt>
   0x0000090f <+177>:	add    esp,0x10
   0x00000912 <+180>:	sub    esp,0xc
   0x00000915 <+183>:	lea    eax,[ebx-0x208a]
   0x0000091b <+189>:	push   eax
   0x0000091c <+190>:	call   0x590 <puts@plt>
   0x00000921 <+195>:	add    esp,0x10
   0x00000924 <+198>:	sub    esp,0xc
   0x00000927 <+201>:	lea    eax,[ebx-0x2082]
   0x0000092d <+207>:	push   eax
   0x0000092e <+208>:	call   0x590 <puts@plt>
   0x00000933 <+213>:	add    esp,0x10
   0x00000936 <+216>:	mov    eax,DWORD PTR [ebx-0x10]
   0x0000093c <+222>:	mov    eax,DWORD PTR [eax]
   0x0000093e <+224>:	sub    esp,0xc
   0x00000941 <+227>:	push   eax
   0x00000942 <+228>:	call   0x570 <fflush@plt>
   0x00000947 <+233>:	add    esp,0x10
   0x0000094a <+236>:	sub    esp,0x8
   0x0000094d <+239>:	lea    eax,[ebp-0xd4]
   0x00000953 <+245>:	push   eax
   0x00000954 <+246>:	lea    eax,[ebx-0x206e]
   0x0000095a <+252>:	push   eax
   0x0000095b <+253>:	call   0x5c0 <__isoc99_scanf@plt>
```
