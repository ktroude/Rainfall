# RainFall CTF - Level0

## Reconnaissance

### Fichier trouvé
```bash
level0@RainFall:~$ ls -l
total 732
-rwsr-x---+ 1 level1 users 747441 Mar  6  2016 level0
```

**Observations :**
- Exécutable avec SUID bit activé (`s` dans les permissions)
- Appartient à `level1` (propriétaire) et `users` (groupe)
- Peut être exécuté avec les privilèges de `level1`

## Analyse statique

### Extraction et reverse engineering
- Téléchargement via `scp`
- Analyse avec **Ghidra**

### Code source décompilé

```c
undefined4 main(undefined4 param_1,int param_2)
{
  int iVar1;
  char *local_20;
  undefined4 local_1c;
  __uid_t local_18;
  __gid_t local_14;
  
  iVar1 = atoi(*(char **)(param_2 + 4));
  if (iVar1 == 0x1a7) {
    local_20 = strdup("/bin/sh");
    local_1c = 0;
    local_14 = getegid();
    local_18 = geteuid();
    setresgid(local_14,local_14,local_14);
    setresuid(local_18,local_18,local_18);
    execv("/bin/sh",&local_20);
  }
  else {
    fwrite("No !\n",1,5,(FILE *)stderr);
  }
  return 0;
}
```

## Analyse du comportement

### Logique du programme
1. **Récupération de l'argument** : `atoi(*(char **)(param_2 + 4))` convertit le premier argument en entier
2. **Comparaison** : Vérifie si l'argument == `0x1a7`
3. **Conversion hexadécimal** : `0x1a7` = `423` en décimal
4. **Escalade de privilèges** : Si la condition est vraie :
   - Récupère les UID/GID effectifs
   - Définit les privilèges avec `setresuid()` et `setresgid()`
   - Lance un shell `/bin/sh`

### Vulnérabilité
Le programme vérifie simplement si l'argument fourni est égal à `423`. Si c'est le cas, il lance un shell avec les privilèges de `level1`.

## Exploitation

### Commande d'exploitation
```bash
level0@RainFall:~$ ./level0 423
```

### Vérification de l'escalade de privilèges
```bash
$ whoami
level1
```

### Récupération du flag
```bash
$ ls -la /home/user/level1/
total 17
dr-xr-x---+ 1 level1 level1   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level1 level1  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level1 level1 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level2 users  5138 Mar  6  2016 level1
-rw-r--r--+ 1 level1 level1   65 Sep 23  2015 .pass
-rw-r--r--  1 level1 level1  675 Apr  3  2012 .profile

$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```

## Résultats

### Flag obtenu
```
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```

### Accès niveau suivant
- **Utilisateur** : `level1`
- **Prochain challenge** : `/home/user/level1/level1`

## Notes techniques

- **Type de vulnérabilité** : Vérification d'authentification faible (hardcoded value)
- **Technique d'exploitation** : Argument prédictible
- **Impact** : Escalade de privilèges locale
- **Difficulté** : Débutant