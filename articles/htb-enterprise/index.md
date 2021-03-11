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
