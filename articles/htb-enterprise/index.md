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

Pour calculer ce padding nous allons voir 3 solutions :

### 1st solution

```py
gdb-peda$ info functions  # Print binary's functions
   [...]
gdb-peda$ disassemble main_menu 
Dump of assembler code for function main_menu:
   0x0000085e <+0>:	push   ebp
   0x0000085f <+1>:	mov    ebp,esp
   0x00000861 <+3>:	push   ebx
   0x00000862 <+4>:	sub    esp,0x1a4
   [...]
   0x00000947 <+233>:	add    esp,0x10
   0x0000094a <+236>:	sub    esp,0x8
   0x0000094d <+239>:	lea    eax,[ebp-0xd4]
   0x00000953 <+245>:	push   eax
   0x00000954 <+246>:	lea    eax,[ebx-0x206e]
   0x0000095a <+252>:	push   eax
   0x0000095b <+253>:	call   0x5c0 <__isoc99_scanf@plt>
   [...]
gdb-peda$ p/d 0xd4  # Convert hex to dec with gdb
$1 = 212
```

On récupére la valeur du lea juste avant la fonction stdin et on convertit cette valeur hexadécimal en décimal et on obtient un buffer de 212 chars.

### 2nd solution

Lorsque l’on utilise ce pattern pour causer un buffer overflow à l’intérieur d’un debugger, nous pouvons identifier exactement quels caractères écrasent l'adresse de retour.

Tout d'abord je vais créer un pattern de 500 bytes :

```py
gdb-peda$ pattern create 500
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%SA%pA%TA%qA%UA%rA%VA%tA%WA%uA%XA%vA%YA%wA%ZA%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGAscAs2AsHAsdAs3AsIAseAs4AsJAsfAs5AsKAsgAs6A'
```

Ensuite je vais run le programme avec cette structure :

![pattern_search](https://i.imgur.com/g8tVTdB.png)

Nous trouvons encore une fois 212 octets.

### 3rd solution

