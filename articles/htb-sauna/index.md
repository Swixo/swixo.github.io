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

![namelist_wordlist_kerbrute](https://i.imgur.com/d4Cw3cY.png)
