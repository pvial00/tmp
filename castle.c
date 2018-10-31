#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dyefamily.c"
#include "darkcipher.c"
#include "h4a.c"
#include "ganja.c"

void usage() {
    printf("DarkCastle - by KryptoMagik\n\n");
    printf("Algorithms:\n***********\n\nDark      256 bit\nWrzeszcz  128 bit\nRedDye    128 bit\nBlueDye   256 bit\n\n");
    printf("Usage: dark <algorithm> <-e/-d> <input file> <output file> <password>\n\n");
}

void dark_encrypt(char *infile_name, long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) { 
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char *mac[mac_length];
    unsigned char *mac_key[key_length];
    unsigned char *key[key_length];
    ganja_kdf(password, strlen(password), key, kdf_iterations, key_length, kdf_salt);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    unsigned char nonce[nonce_length];
    reddye_random(&nonce, nonce_length);
    fwrite(nonce, 1, nonce_length, outfile);
    fread(msg, 1, fsize, infile);
    crypt(msg, key, nonce, fsize);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    ganja_kdf(key, key_length, mac_key, kdf_iterations, key_length, kdf_salt);
    ganja_hmac(msg, fsize, mac, mac_key, key_length, kdf_salt);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void dark_decrypt(char *infile_name, long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char *mac[mac_length];
    unsigned char *mac_key[key_length];
    unsigned char *key[key_length];
    unsigned char *msg;
    unsigned char *mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    ganja_kdf(password, strlen(password), key, kdf_iterations, key_length, kdf_salt);
    ganja_kdf(key, key_length, mac_key, kdf_iterations, key_length, kdf_salt);
    fread(mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), mac_verify, mac_key, key_length, kdf_salt);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-nonce_length);
        unsigned char *nonce[nonce_length];
        fseek(infile, mac_length, SEEK_SET);
        fread(nonce, 1, nonce_length, infile);
        fread(msg, 1, (fsize - mac_length - nonce_length), infile);
        fclose(infile);
        crypt(msg, key, nonce, (fsize - mac_length - nonce_length));
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - nonce_length), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered.\n");
    }
}

void reddye_encrypt(char *infile_name, long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) { 
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char *mac[mac_length];
    unsigned char *mac_key[key_length];
    unsigned char *key[key_length];
    ganja_kdf(password, strlen(password), key, kdf_iterations, key_length, kdf_salt);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    unsigned char nonce[nonce_length];
    reddye_random(&nonce, nonce_length);
    fwrite(nonce, 1, nonce_length, outfile);
    fread(msg, 1, fsize, infile);
    reddye_crypt(msg, key, nonce, fsize, key_length);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    ganja_kdf(key, key_length, mac_key, kdf_iterations, key_length, kdf_salt);
    ganja_hmac(msg, fsize, mac, mac_key, key_length, kdf_salt);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void reddye_decrypt(char *infile_name, long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char *mac[mac_length];
    unsigned char *mac_key[key_length];
    unsigned char *key[key_length];
    unsigned char *msg;
    unsigned char *mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    ganja_kdf(password, strlen(password), key, kdf_iterations, key_length, kdf_salt);
    ganja_kdf(key, key_length, mac_key, kdf_iterations, key_length, kdf_salt);
    fread(mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), mac_verify, mac_key, key_length, kdf_salt);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-nonce_length);
        unsigned char *nonce[nonce_length];
        fseek(infile, mac_length, SEEK_SET);
        fread(nonce, 1, nonce_length, infile);
        fread(msg, 1, (fsize - mac_length - nonce_length), infile);
        fclose(infile);
        reddye_crypt(msg, key, nonce, (fsize - mac_length - nonce_length), key_length);
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - nonce_length), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered.\n");
    }
}

void bluedye_encrypt(char *infile_name, long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) { 
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char *mac[mac_length];
    unsigned char *mac_key[key_length];
    unsigned char *key[key_length];
    ganja_kdf(password, strlen(password), key, kdf_iterations, key_length, kdf_salt);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    unsigned char nonce[nonce_length];
    reddye_random(&nonce, nonce_length);
    fwrite(nonce, 1, nonce_length, outfile);
    fread(msg, 1, fsize, infile);
    bluedye_crypt(msg, key, nonce, fsize);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    ganja_kdf(key, key_length, mac_key, kdf_iterations, key_length, kdf_salt);
    ganja_hmac(msg, fsize, mac, mac_key, key_length, kdf_salt);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void bluedye_decrypt(char *infile_name, long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char *mac[mac_length];
    unsigned char *mac_key[key_length];
    unsigned char *key[key_length];
    unsigned char *msg;
    unsigned char *mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    ganja_kdf(password, strlen(password), key, kdf_iterations, key_length, kdf_salt);
    ganja_kdf(key, key_length, mac_key, kdf_iterations, key_length, kdf_salt);
    fread(mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), mac_verify, mac_key, key_length, kdf_salt);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-nonce_length);
        unsigned char *nonce[nonce_length];
        fseek(infile, mac_length, SEEK_SET);
        fread(nonce, 1, nonce_length, infile);
        fread(msg, 1, (fsize - mac_length - nonce_length), infile);
        fclose(infile);
        bluedye_crypt(msg, key, nonce, (fsize - mac_length - nonce_length));
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - nonce_length), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered.\n");
    }
}

void wrzeszcz_encrypt(char *infile_name, long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) { 
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char *mac[mac_length];
    unsigned char *mac_key[key_length];
    unsigned char *key[key_length];
    ganja_kdf(password, strlen(password), key, kdf_iterations, key_length, kdf_salt);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    unsigned char nonce[nonce_length];
    reddye_random(&nonce, nonce_length);
    fwrite(nonce, 1, nonce_length, outfile);
    fread(msg, 1, fsize, infile);
    wrzeszcz_crypt(msg, key, nonce, fsize, key_length);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    ganja_kdf(key, key_length, mac_key, kdf_iterations, key_length, kdf_salt);
    ganja_hmac(msg, fsize, mac, mac_key, key_length, kdf_salt);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void wrzeszcz_decrypt(char *infile_name, long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char *mac[mac_length];
    unsigned char *mac_key[key_length];
    unsigned char *key[key_length];
    unsigned char *msg;
    unsigned char *mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    ganja_kdf(password, strlen(password), key, kdf_iterations, key_length, kdf_salt);
    ganja_kdf(key, key_length, mac_key, kdf_iterations, key_length, kdf_salt);
    fread(mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), mac_verify, mac_key, key_length, kdf_salt);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-nonce_length);
        unsigned char *nonce[nonce_length];
        fseek(infile, mac_length, SEEK_SET);
        fread(nonce, 1, nonce_length, infile);
        fread(msg, 1, (fsize - mac_length - nonce_length), infile);
        fclose(infile);
        wrzeszcz_crypt(msg, key, nonce, (fsize - mac_length - nonce_length), key_length);
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - nonce_length), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered.\n");
    }
}
    
void main(int argc, char *argv[]) {
    unsigned char kdf_salt[] = "CastleCipherSui";
    int kdf_iterations = 10000;

    char *encrypt_symbol = "-e";
    char *decrypt_symbol = "-d";

    int reddye_nonce_length = 8;
    int bluedye_nonce_length = 8;
    int dark_nonce_length = 16;
    int wrzeszcz_nonce_length = 8;

    int reddye_key_length = 32;
    int bluedye_key_length = 32;
    int dark_key_length = 32;
    int wrzeszcz_key_length = 32;

    int dark_mac_length = 32;
    int bluedye_mac_length = 32;
    int reddye_mac_length = 32;
    int wrzeszcz_mac_length = 32;

    if (argc != 6) {
        usage();
        exit(1);
    }

    FILE *infile, *outfile;
    char *infile_name, *outfile_name;
    char *algorithm = argv[1];
    char *mode = argv[2];
    infile_name = argv[3];
    outfile_name = argv[4];
    unsigned char *password = argv[5];
    infile = fopen(infile_name, "rb");
    fseek(infile, 0, SEEK_END);
    long fsize = ftell(infile);
    fclose(infile);
    //fseek(infile, 0, SEEK_SET);
    //unsigned char *msg;

    if (strcmp(algorithm, "dark") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            dark_encrypt(infile_name, fsize, outfile_name, dark_key_length, dark_nonce_length, dark_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            dark_decrypt(infile_name, fsize, outfile_name, dark_key_length, dark_nonce_length, dark_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
    else if (strcmp(algorithm, "reddye") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            reddye_encrypt(infile_name, fsize, outfile_name, reddye_key_length, reddye_nonce_length, reddye_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            reddye_decrypt(infile_name, fsize, outfile_name, reddye_key_length, reddye_nonce_length, reddye_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
    else if (strcmp(algorithm, "bluedye") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            bluedye_encrypt(infile_name, fsize, outfile_name, bluedye_key_length, bluedye_nonce_length, bluedye_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            bluedye_decrypt(infile_name, fsize, outfile_name, bluedye_key_length, bluedye_nonce_length, bluedye_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
    else if (strcmp(algorithm, "wrzeszcz") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            wrzeszcz_encrypt(infile_name, fsize, outfile_name, wrzeszcz_key_length, wrzeszcz_nonce_length, wrzeszcz_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            wrzeszcz_decrypt(infile_name, fsize, outfile_name, wrzeszcz_key_length, wrzeszcz_nonce_length, wrzeszcz_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
}
