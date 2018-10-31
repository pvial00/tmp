#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "ganja.c"

void main(int arc, char *argv[]) {
    char *filename = argv[1];
    FILE *infile;
    infile = fopen(filename, "rb");
    fseek(infile, 0, SEEK_END);
    long fsize = ftell(infile);
    fseek(infile, 0, SEEK_SET);
    unsigned char *data;
    data = (unsigned char *) malloc(fsize);
    fread(data, 1, fsize, infile);
    fclose(infile);
    unsigned char d[32] = {0};
    char hex_out[32*2+1];
    unsigned char salt[4] = {0};

    ganja_digest(data, fsize, d, salt);
    for (int x = 0; x < 32; x++) {
        sprintf(&hex_out[x*2], "%02X", d[x]);
    }
    printf("%s\n", hex_out);
}
