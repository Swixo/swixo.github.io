Bonjour à tous, aujourd'hui je tenais à vous faire un walkthrough sur la machine **Sauna** de **HackTheBox** qui est un environnement **Active Directory** et une box très sympatique à root... ;)

# Recon

## Nmap

```bash
└─$ nmap -sC -sV -T4 -oA sauna 10.10.10.175 -Pn
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-21 01:45 CET
Nmap scan report for 10.10.10.175
Host is up (0.13s latency).
Not shown: 988 filtered ports
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Egotistical Bank :: Home
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-02-21 07:45:37Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h00m01s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-02-21T07:45:46
|_  start_date: N/A
```

Nous pouvons énumérer le Domain Controller de l'AD avec [enum4linux](https://github.com/CiscoCXSecurity/enum4linux) ou manuellement avec ldapsearch comme ceci :

![enum_DC](https://i.imgur.com/RQKXEQs.png)

Nous pouvons enregistrer ce nom de domaine, avec comme TLD .local, dans notre ficher [/etc/hosts](https://www.configserverfirewall.com/ubuntu-linux/hosts-file/).

### Enumeration SMB Server

L'accès anonymous est autorisé mais aucun share est retourné.

![enum_SMB](https://i.imgur.com/xID4GwS.png)

### Enumeration Web Server

Nous commencons avec un webdir qui ne donne rien d'intéréssant :

![webdir](https://i.imgur.com/jZAIuBd.png)

Allons donc voir ce que le site web contient à la main, nous remarquons un about.html qui présente les employés de la banque dont 1 security manager :

![employe](https://i.imgur.com/nCFx9WH.png)

### Enumeration Kerberos

À l'aide du nom des employés nous pouvons générer une wordlist personnalisée afin de trouver des potentiels users.

Pour cela, j'ai utilisé les [rules hashcat](https://hashcat.net/wiki/doku.php?id=rule_based_attack) et [kerbrute](https://github.com/ropnop/kerbrute) :

![namelist_wordlist_kerbrute](https://i.imgur.com/zvKBlps.png)

Nous obtenons un user nommé fsmith. 😄

# Getting credentials for fsmith

Nous pouvons tenter d'abuser d'une fonctionnalité de Kerberos avec une méthode d'attaque appelée **ASREPRoasting**. L'ASReproasting se produit lorsqu'un compte utilisateur a le privilège
"Ne nécessite pas de pré-authentification". Cela signifie que le compte n'a pas besoin de fournir une identification valide avant de demander un ticket Kerberos sur le compte utilisateur spécifié.

Un outil de **[impacket](https://github.com/SecureAuthCorp/impacket)** nommé **[GetNPUsers](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py)** permet d'interroger les comptes ASReproastable depuis le **Key Distribution Center** (KDC).

![GetNPUsers_exploit](https://i.imgur.com/XbWQxgW.png)

Nous avons enfin le hash **Kerberos 5 AS-REP etype 23** de Fergus Smith, le security manager de la banque ! 🙂

Utilisons hashcat :

![crackhashfsmith](https://i.imgur.com/Hcd07tr.png)

Maintenant nous avons les creds de fsmith ! 😁

Lors de notre scan nmap, nous avons vu que le port **WinRM** est ouvert, (HTTP : 5985 // HTTPS : 5986) nous pouvons donc nous connecter à distance avec [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) :

![evilwinrm_foothold](https://i.imgur.com/Az1GbP3.png)

Nous avons un foothold sur la machine, c'est parti pour l'escalation de privilèges ! 😀

# Privilege Escalation

### Pivot to svc_loanmgr (WinLogon credentials)

Après une énumeration avec BloodHound sans succès, j'ai décidé de continuer à énumérer la machine et ses fichiers manuellement.

Des informations intéressantes peuvent être récupérées au niveau de la clé de registre [WinLogon](https://www.rapid7.com/db/vulnerabilities/WINDOWS-AUTOLOGIN-ENABLED/) :

![winlogon](https://i.imgur.com/opCS4zS.png)

Maintenant que nous avons les creds au service account (svc) nous nous connectons dessus. 😉

### Administrator Access (DCSync Attack)

Nous allons utiliser **Bloodhound** pour énumérer et visualiser l' Active Directory, et identifier les procédures d'attaques possibles qui nous permettront d'élever nos privilèges.
Pour cela nous allons lancer **SharpHound** sur la machine distante afin de récupèrer les fichiers json qu'on va pouvoir analyser sur BloodHound:

![sharphound](https://i.imgur.com/zqRv7Ux.png)

L'utilisateur svc_loanmgr@EGOTISTICAL-BANK.LOCAL a le privilège DS-Replication-Get-Changes-All sur le domaine EGOTISTICAL-BANK.LOCAL :

![bloodhound](https://i.imgur.com/50XCDxM.png)

Avec les privilèges GetChanges et GetChangesAll, on peut effectuer une [attaque DCSync](http://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/) pour obtenir le hash NTLM de l'Administrator. 

Pour cela nous allons utiliser mimikatz :

