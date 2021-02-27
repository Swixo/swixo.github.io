---
title: "Attaque par bit flipping"
description: sam.png
tags: ["Nous allons ici expliquer ce qui se cache derrière la notion de bit flipping. Une attaque par retournement de bits est une attaque sur un chiffrement cryptographique dans laquelle l'attaquant peut modifier le texte chiffré de manière à entraîner un changement prévisible du texte en clair, bien que l'attaquant ne soit pas en mesure d'apprendre le texte en clair lui-même.
"]
---

Nous allons ici expliquer ce qui se cache derrière la notion de bit flipping. Une attaque par retournement de bits est une attaque sur un chiffrement cryptographique dans laquelle l'attaquant peut modifier le texte chiffré de manière à entraîner un changement prévisible du texte en clair, bien que l'attaquant ne soit pas en mesure d'apprendre le texte en clair lui-même.

J'étais confontré à un retournement de bits sur HTB dans la boxe Lazy, sur une vulnérabilité de type `Padding Oracle` et j'ai réussi à m'introduire dans le compte administrateur en changement seulement les bits du `Cookie`, vous comprendrez mieux par la suite.

# Théorie

Chaque fois que vous vous connectez sur un `site web`, le serveur vous donnent un `Cookie`, pour la simple et bonne raison que cela permet tout simplement de maintenir une session entre le client et le serveur, si une personne récupère vos cookies, il serait capable de se connecter à votre compte sans mettre les identifiants d'identifications, c'est pour cela que la sécurité est important !

# Fonctionnement du CBC

Si votre message que vous souhaitez chiffrer est « hello », chaque fois que vous chiffrez le mot «hello», il en résultera toujours la même sortie chiffrée. Cela pose un risque de sécurité grave car un attaquant peut procéder à une attaque en chiffrant simplement une liste de mots, puis en les comparant aux valeurs chiffrées, révélant ainsi le jeton. L'attaquant peut alors créer son propre token, le crypter et l'utiliser pour se connecter en tant qu'autre utilisateur. CBC est un moyen de randomiser la sortie de la valeur chiffrée.

![forthebadge made-with-python](https://www.researchgate.net/profile/Mousa_Farajallah/publication/308826472/figure/fig1/AS:391837119467524@1470432657367/AES-encryption-system-in-CFB-mode.png)

Le système est simple, le chiffrement `CBC` fonctionne par bloc, c'est-à-dire que pour qu'un bloc soit `XORED`, il a besoin du bloc précédent pour qu'il soit `XORED`.

    C¹ = E(P¹ ⊕ IV)
    Cⁿ = E(Pⁿ ⊕ Cⁿ - 1) — si n > 1

Vous me poserez la question, comment la première valeur du bloc peut être chiffré, si il n'a pas de précédent ?
C'est là que le système `IV` (Initialization vector ou Vecteur d'initialisation) rentre en jeu, il randomise une donnée aléatoire pour que il soit XORED avec le premier bloc et ainsi de suite jusqu'au dernier bloc, la formule ci-dessus résume la finalité.

Donc, l'attaque est relativement simple, supposons que nous avons un utilisateur qui se nomme `admin` et le chiffrement du `Cookie` est `21232f297a57a5a743894a0e4a801fc3`, notre but concrètement est de changer la valeur `admin` en changeant seulement les bits du `Cookie`, par exemple `vb232f297a57a5a743894a0e4a801fc3` qui deviendra `bdmin`, l'idée est là, c'est de changer le comportement du `Cookie` et de lui afficher quelque chose d'autre pour accéder à un compte.

# Pratique

Dans mon cas, j'utiliserai un serveur `XAMPP` et d'installer `Mullitidae`, Mullitidae est un environnement de `pentest`, n'hésitez pas à l'[installer](https://www.owasp.org/index.php/OWASP_Mutillidae_2_Project) pour faire des testes intéréssants. Démarrons simplement le service `APACHE` et `MYSQL`

![forthebadge made-with-python](https://github.com/0xEX75/0xEX75.github.io/blob/master/Capture.PNG?raw=true)

Dans la version 2.6.10 de Mutilidae, il existe une page appelée Niveau de privilège utilisateur. Ceci est conçu pour pratiquer l'attaque de retournement de bits CBC. Il se trouve sous: OWASP 2013, Authentification interrompue et gestion de session, Échelle de privilèges, afficher les privilèges des utilisateurs. 

Comme vous pouvez le voir, le but de ce défi est de changer l'utilisateur et le groupe en `000`. La première chose dont nous avons besoin est l'`IV`. Nous devons utiliser un proxy qui se situe entre nous et le serveur pour intercepter la communation entre le `client` et le `serveur`. J'utiliserai `BurpSuite` pour cela. `BurpSuite` est un outil utilisé pour aider au pentesting d'applications Web. vous devez configurer votre navigateur pour passer par le proxy Burp. La configuration du `BurpSuite` est hors de portée pour ce poste.

![forthebadge made-with-python](https://raw.githubusercontent.com/0xEX75/0xEX75.github.io/master/000.PNG)

Ensuite, interceptons la communication entre le client et serveur pour falsifier la communication entre le client et le serveur à l'aide de `BurpSuite`. 

Si nous modifions les deux premières valeurs par `FFc24fc1ab650b25b4114e93a98f1eba`, nous aurons une chose inintellegible en sortie, ce qui prouve que nous avons le pouvoir sur le `Cookie`.

![forthebadge made-with-python](https://github.com/0xEX75/0xEX75.github.io/blob/master/valeur.PNG)

FFFF4fc1ab650b25b4114e93a98f1eba
FFFFFFc1ab650b25b4114e93a98f1eba
FFFFFFFFab650b25b4114e93a98f1eba
FFFFFFFFFF650b25b4114e93a98f1eba
FFFFFFFFFFFFFFFFb4114e93a98f1eba

Si nous modifions ainsi de suite, nous aurons totalement débordé la sortie standard du système. Ok, donc nous savons le bit que nous devons modifier pour changer la partie du champ ID utilisateur. Notez ceci car nous en aurons besoin plus tard. Continuez à retourner les bits jusqu'à ce que vous arriviez à la partie de l'ID de groupe qui doit être modifiée.

Donc les bits à modifiers sont `6bc24fc1 FF 650b FF b4114e93a98f1eba`, cela nous donnera en sortie :

![forthebadge made-with-python](https://raw.githubusercontent.com/0xEX75/0xEX75.github.io/master/0e.PNG)

Nous avons donc trouvé les bits que nous devons modifier pour modifier les parties correctes de l'ID d'utilisateur et de groupe. L'étape suivante consiste à les modifier de manière à les renvoyer sous forme de zéro. Nous voyons que l'ID de utilisateur que nous avons envoyé `FF` a renvoyé « e ». Le FF que nous avons envoyé était une valeur hexadécimale et le « e » est un littéral donc le «e» doit être converti en HEX. Utilisez `Python` pour décoder « e » en HEX renvoie `65`. Maintenant, nous XORons `FF` avec `65`.

    $ import binascii
    $ binascii.hexlify(b'e')
    '65'
    $ print hex(0xff ^ 0x65)
    '0x9a'
    
La valeur XORed renvoie la valeur HEX `9a`. Pour obtenir complètement la valeur `0`, nous devons convertir `0` en `HEX` ce qui nous donnera `30` et ensuite de `XOR` cette valeur avec `9a` 

    $ hex(0x30 ^ 0x9a)
    '0xaa'

Donc maintenant le `Cookie` prend cette forme `6bc24fc1 aa 650b FF b4114e93a98f1eba`, il nous manque juste le dernier `FF`, si nous regardons à travers `BurpSuite`, nous verrons bien que le `000` est bien présent, ce qui signifie que nous sommes dans la bonne voie.

![forthebadge made-with-python](https://github.com/0xEX75/0xEX75.github.io/blob/master/done.PNG?raw=true)

Donc, nous sommes sur un problème, il y a un point d'interrogation inintellegible, nous devons trouver une valeur qui peut être lisible, donc essayons par exemple `31` cela nous renvoie un pourcentage, donc il nous reste plus que à convertir `%` en HEX ce qui nous donnera `25`, ensuite de XOR `0x31` avec `0x25` (`0x14`) et enfin de `XOR` `0x30` avec `0x14`.

    $ import binascii
    $ binascii.hexlify(b'%')
    '25'
    $ print hex(0x31 ^ 0x25)
    0x14
    $ hex(0x30 ^ 0x14)
    '0x24'
    
C'est parfait, nous sommes root, 6bc24fc1`aa`650b`24`b4114e93a98f1eba.

![forthebadge made-with-python](https://github.com/0xEX75/0xEX75.github.io/blob/master/root.PNG?raw=true)

# Conclusion

Voilà, nous arrivons enfin au bout de cet article qui, je l’espère, vous aura plus. J’ai essayer de vous expliquez le fonctionnement de la technique par bit flipping, n’hésitez pas à me contacter sur les réseaux sociaux, je suis toujours disponible pour vous répondre.
