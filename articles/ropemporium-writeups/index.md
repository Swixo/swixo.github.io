---
title: "ROP Emporium - Writeups"
description: Writeups des challenges x86_64 de ROP Emporium 
---

Aujourd'hui je vous propose mes writeups des challenges x86_64 de [ROP Emporium](https://ropemporium.com/). Vous pouvez retrouver les [scripts de solution](https://github.com/nuts7/nuts7.github.io/tree/master/articles/ropemporium-writeups) sur mon GitHub. 😀

# Sommaire
1. [ret2win](#ret2win-writeup)
2. [split](#split-writeup)
3. [callme](#callme-writeup)
4. [write4](#write4-writeup)
5. [badchars](#badchars-writeup)
6. [fluff](#fluff-writeup)
7. [pivot](#pivot-writeup)
8. [ret2csu](#ret2csu-writeup)

<div id='ret2win-writeup'/>
# ret2win

<div id='split-writeup'/>
# split

<div id='callme-writeup'/>
# callme

<div id='write4-writeup'/>
# write4

Après lecture de la description du [challenge write4](https://ropemporium.com/challenge/write4.html), nous comprenons que nous allons devoir **write flag.txt** en mémoire dans une **section du binaire accessible en écriture** et **call** la fonction `print_file()` dans la **PLT**. Il est spécifié que `print_file()` prend comme seul argument **l'emplacement mémoire** de flag.txt.

```py
❯ readelf -S write4
Il y a 29 en-têtes de section, débutant à l'adresse de décalage 0x1980:

En-têtes de section :
<...>
  [23] .data             PROGBITS         0000000000601028  00001028
       0000000000000010  0000000000000000  WA       0     0     8
  [24] .bss              NOBITS           0000000000601038  00001038
       0000000000000008  0000000000000000  WA       0     0     1
<..>
Clé des fanions :
  W (écriture), A (allocation), X (exécution), M (fusion), S (chaînes), I (info),
  L (ordre des liens), O (traitement supplémentaire par l'OS requis), G (groupe),
  T (TLS), C (compressé), x (inconnu), o (spécifique à l'OS), E (exclu),
  l (grand), p (processor specific)
  ```

<div id='badchars-writeup'/>
# badchars

<div id='fluff-writeup'/>
# fluff

<div id='pivot-writeup'/>
# pivot

<div id='ret2csu-writeup'/>
# ret2csu
