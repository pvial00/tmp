#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "ganja.c"

void main(int arc, char *argv[]) {
    char *password = argv[1];
    FILE *infile;
    int keylen = 32;
    unsigned char d[32] = {0};
    unsigned char salt[4] = {0};
    char hex_out[32*2+1];

    ganja_kdf(password, strlen(password), d, 10000, keylen, salt);
    for (int x = 0; x < keylen; x++) {
        sprintf(&hex_out[x*2], "%02X", d[x]);
    }
    printf("%s\n", hex_out);
}
