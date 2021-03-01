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

Proxychains fonctionne pour les paquets TCP mais pas UDP, donc pour nmap par exemple si tu veux scanner à travers un proxy il va falloir rajouter le paramètre -sT pour dire à nmap de faire un scan TCP (et non SYN par défaut)

Proxychains va prendre les proxies de haut en bas, deplus il y a plusieurs options :

- Strict chaining, proxychains suit obligatoirement le chemin donné dans `/etc/proxychains.conf`
- Dynamic chaining, proxychains va d'abord détecter si le proxy est up avant de l'utiliser
- Random chaining, tout est dans le nom, il va pas suivre un ordre précis

