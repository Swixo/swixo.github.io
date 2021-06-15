---
title: "Decoding opcodes"
description: Comment décoder des opcodes ?
---

# Sommaire
1. [Qu'est ce qu'un opcode ?](#what_is_opcode)
2. [Le format des instructions des architectures Intel 64 et IA-32](#instruction_format)

<br/>

<div id='what_is_opcode'/>
# Qu'est ce qu'un opcode ?

Tout d'abord, un opcode est une **instruction** (écrite hexadécimal) en **langage machine** qui spécifie l'opération à effectuer. Les opcodes sont les **instructions assembleur** notés en **hexadécimal** que le CPU va exécuter. 
Un opcode primaire peut avoir une longueur de 1, 2 ou 3 octets.

L'**hexdump** d'un binaire est l'ensemble des opcodes du programme. Voici un sample des opcodes d'un hello world en C compilé :

```py
❯ xxd helloworld
<...>
000002a0: 0100 0000 0000 0000 2f6c 6962 3634 2f6c  ......../lib64/l
000002b0: 642d 6c69 6e75 782d 7838 362d 3634 2e73  d-linux-x86-64.s
000002c0: 6f2e 3200 0400 0000 1400 0000 0300 0000  o.2.............
000002d0: 474e 5500 244c 91c8 e319 bc06 2283 5226  GNU.$L......".R&
<...>
```

<div id='instruction_format'/>
# Le format des instructions des architectures Intel® 64 et IA-32

Premièrement les instructions sont composées de :

- Préfixes d'instruction (facultatif)
- Octets d'opcode primaire (3 bytes maximum)
- Spécificateur de forme d'adressage (si nécessaire) constitué d'un octet **Mod R/M** et parfois d'un octet **SIB** (Scale-Index-Base)
- Déplacement (si nécessaire)
- Un champ de données immédiates (si nécessaire)

Voici un schéma qui résume le format des instructions en architecture Intel® 64 et IA-32 :

<p align="center">
  <img src="https://i.imgur.com/pJfQoOO.png">
</p>


