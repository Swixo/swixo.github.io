---
title: "Déchiffrement d'un mot de passe CISCO de type 7."
description: test.png
tags: ["Dans cet article je vous présente comment.."]
---

Bien que vous deviez utiliser `MD5` ou `SHA256` pour la sécurité par mot de passe, les mots de passe de type 7 sont toujours utilisés et j’ai donc pensé que ce serait un exercice d’apprentissage amusant.

Aujourd'hui dans cet article je vais vous expliquez briévement comment déchiffrer un mot de passe `CISCO` de type 7 manuellement, j'ai bien dis manuellement.

Le `'service password-encryption'` ou mot de passe de type 7 est basé sur un algorithme de chiffrement faible propriétaire connu utilisant `XOR` et peut être reconnu dans le fichier de configuration.

![Flower](https://media.giphy.com/media/diUKszNTUghVe/giphy.gif)

Avant de rentrer dans le sujet, nous devons comprendre comment fonctionne le système `XOR` c'est indispensable, mais vous verrez que j'vais pas beaucoup compliqué les choses.. Croyez-moi c'est simple.

Fonctiomment de XOR
----
Le XOR est un opérateur logique qui correspond à un "OU exclusif" : c'est le (X OU Y) qu'on utilise en logique mais qui exclue le cas où X et Y sont simultanément vrais. Voici sa table de vérité :

![Flower](https://image.noelshack.com/fichiers/2019/48/7/1575208363-capture-du-2019-12-01-14-39-48.png)

