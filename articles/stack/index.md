Bonjour à tous, aujourd'hui nous utilisons des programmes sans comprendre la gestion de mémoire qui se passe derrière tout cela, c'est pourquoi je vous propose aujourd’hui de découvrir le fonctionnement de la pile en informatique et comment manipuler cette dernière. 😀

## La stack, une structure LIFO

Lorsqu'un programme est lancé sur un PC, une zone de mémoire est allouée au sein de laquelle les données manipulés par le programme seront stockés. La pile est un emplacement mémoire défini par deux bornes, la première borne est un pointeur qui indique l'adresse du **bas de la pile**, la seconde borne est un pointeur indiquant l'adresse du **haut de la pile**, le registre **RSP**, autrement dit la Stack Pointer.

Cette structure de données est basé sur le principe **LIFO**, (Last In, First Out) __c'est-à-dire que la dernière donnée arrivée est la première sortie__. Prenons l'exemple d'un paquet de chips Pringles, mettons une première chips nature, une deuxième chips au paprika, une troisième chips piquante. La troisième (la dernière) chips piquante sera retiré du paquet de chips avant les autres, c'est le principe de la pile... Bref, un court schéma s'impose. 😁


![alt text](https://upload.wikimedia.org/wikipedia/it/thumb/b/b5/FIFO-LIFO.svg/1200px-FIFO-LIFO.svg.png)


**Plus on empile des valeurs dans la stack, plus les adresses diminuent**, comme nous pouvons voir sur le schéma de GDB-PEDA. 


![alt text](https://i.imgur.com/vjCMPG1.png)


## Comment manipuler la stack ?

Tout d'abord, nous allons introduire les instructions ```PUSH``` et ```POP``` avec un exemple simple.

L'instruction **PUSH register** met la valeur du registre dans RSP, le registre en haut de la pile.
L'instruction **POP register** enlève la valeur de RSP pour la mettre dans le registre destination.

**Exemple :**
```

BITS 64

global _start

section .text

_start:
	mov rax, 1337 ; on met 1337 dans RAX
	push rax  ; on mets RAX dans RSP (haut de la stack)
	pop rdi  ; on mets RSP dans RDI
	
  ```
  **Schéma de l'instruction PUSH via l'exemple :**

![alt text](https://i.imgur.com/SjprmnM.png)

**Schéma de l'instruction POP via l'exemple :**

![alt text](https://i.imgur.com/1DmYUFl.png)

