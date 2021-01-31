Bonjour à tous, je vous présente mon **write-up** qui porte sur la machine **Olympus** de **HackTheBox** qui était assez cool et qui m'a apprit des choses que je n'avais jamais vu auparavant surtout dans un CTF. Elle n'est pas difficile mais très intéréssante et amusante à root... 😀

# Recon

## Nmap
  
```
# Nmap 7.91 scan initiated Fri Jan 29 17:30:12 2021 as: nmap -sC -sV -oA nmap -Pn olympus.htb
Nmap scan report for olympus.htb (10.10.10.83)
Host is up (0.13s latency).
Not shown: 996 closed ports
PORT     STATE    SERVICE VERSION
22/tcp   filtered ssh
53/tcp   open     domain  (unknown banner: Bind)
| dns-nsid: 
|_  bind.version: Bind
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|     bind
|_    Bind
80/tcp   open     http    Apache httpd
|_http-server-header: Apache
|_http-title: Crete island - Olympus HTB
2222/tcp open     ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-City of olympia
| ssh-hostkey: 
|   2048 f2:ba:db:06:95:00:ec:05:81:b0:93:60:32:fd:9e:00 (RSA)
|   256 79:90:c0:3d:43:6c:8d:72:19:60:45:3c:f8:99:14:bb (ECDSA)
|_  256 f8:5b:2e:32:95:03:12:a3:3b:40:c5:11:27:ca:71:52 (ED25519)
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port53-TCP:V=7.91%I=7%D=1/29%Time=60143823%P=x86_64-unknown-linux-gnu%r
SF:(DNSVersionBindReqTCP,3F,"\0=\0\x06\x85\0\0\x01\0\x01\0\x01\0\0\x07vers
SF:ion\x04bind\0\0\x10\0\x03\xc0\x0c\0\x10\0\x03\0\0\0\0\0\x05\x04Bind\xc0
SF:\x0c\0\x02\0\x03\0\0\0\0\0\x02\xc0\x0c");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port2222-TCP:V=7.91%I=7%D=1/29%Time=6014381E%P=x86_64-unknown-linux-gnu
SF:%r(NULL,29,"SSH-2\.0-City\x20of\x20olympia\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\r\n");
```


Nous pouvons voir que le serveur contient 3 ports ouverts:
1. Port 53 (Serveur DNS)
2. Port 80 (Serveur Web Apache)
3. Port 2222 (Serveur SSH)

### Enumération Serveur DNS

Commencons par intérroger le serveur DNS afin d'afficher l'opcode mnémotechnique **AXFR** avec **dig**. La requete AXFR ne renvoie rien d'intéréssant, cependant un autre nom de domaine peut etre important...

![dig](https://i.imgur.com/IvHQg4g.png)

### Enumération Serveur Web

###### Web Dir

![webdir](https://i.imgur.com/njBhSKT.png)

Rien n'a été trouvé.

###### HTTP Headers

En regardant les headers des requetes et réponses HTTP on sait maintenant que **Xdebug 2.5.5** est en marche sur la machine, ce qui peut permettre aux développeurs de déboguer à distance.

![headers](https://i.imgur.com/UPfH78c.png)

Après quelques recherches, on s'apercoit que cette librairie est touché par une [RCE](https://paper.seebug.org/397/), ce qui va nous permettre d'avoir un premier foothold sur la machine. 😇

