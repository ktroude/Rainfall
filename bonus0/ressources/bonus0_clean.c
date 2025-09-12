#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// mêmes globals implicites que l'original : rien de spécial

// Lit une ligne sur stdin, coupe au '\n', copie MAX 20 octets dans dst
static void read_field(char *dst, const char *label) {
    char buf[0x1000];          // 4096
    puts(label);               // même prompt pour les deux champs
    ssize_t n = read(0, buf, sizeof buf);
    if (n <= 0) return;
    char *nl = strchr(buf, '\n');
    if (nl) *nl = '\0';        // coupe à la fin de ligne
    // ⚠️ pas de '\0' garanti si source a >= 20 octets
    strncpy(dst, buf, 20);
}

// Construit "first + ' ' + last" dans out (taille 54 dans main)
static void build_fullname(char *out) {
    char first[20];
    char last[20];

    read_field(first,  "input:");
    read_field(last,   "input:");

    // ⚠️ first peut ne PAS être nul-terminé → strcpy lit au-delà
    strcpy(out, first);

    // Écrit l'espace et le terminator à la fin de out
    size_t len = 0;
    while (out[len] != '\0') len++;     // strlen maison de l'asm
    out[len]   = ' ';
    out[len+1] = '\0';

    // ⚠️ last peut ne PAS être nul-terminé → strcat lit au-delà
    strcat(out, last);
}

int main(void) {
    char fullname[54];          // buffer cible
    build_fullname(fullname);
    puts(fullname);
    return 0;
}
