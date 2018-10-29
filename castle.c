#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dyefamily.c"
#include "darkcipher.c"

void main(int argc, char *argv[]) {
    int keylen = 32;
    unsigned char salt[] = "CastleCipherSuite";
    int iterations = 10000;

    FILE *infile, *outfile;
    char *infile_name, *outfile_name;
    unsigned char *key[32];
    char *algorithm = argv[1];
    infile_name = argv[2];
    outfile_name = argv[3];
    unsigned char *password = argv[4];
    infile = fopen(infile_name, "rb");
    fseek(infile, 0, SEEK_END);
    long fsize = ftell(infile);
    fseek(infile, 0, SEEK_SET);
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, infile);
    fclose(infile);

    if (strcmp(algorithm, "reddye") == 0) {
	bluedye_kdf(password, key, salt, iterations, keylen);
        reddye_crypt(msg, key, key, fsize);
    }
    if (strcmp(algorithm, "wrzeszcz") == 0) {
        reddye_kdf(password, key, salt, iterations, keylen);
	wrzeszcz_crypt(msg, key, key, fsize, keylen);
    }
    if (strcmp(algorithm, "bluedye") == 0) {
        reddye_kdf(password, key, salt, iterations, keylen);
	bluedye_crypt(msg, key, key, fsize);
    }
    if (strcmp(algorithm, "dark") == 0) {
        reddye_kdf(password, key, salt, iterations, keylen);
        crypt(msg, key, key, fsize);
    }
    outfile = fopen(outfile_name, "wb");
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}
