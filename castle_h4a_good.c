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

void main(int argc, char *argv[]) {
    unsigned char kdf_salt[] = "CastleCipherSuite";
    int kdf_iterations = 10000;
    char *encrypt_symbol = "-e";
    char *decrypt_symbol = "-d";
    int reddye_nonce_length = 16;
    int bluedye_nonce_length = 16;
    int dark_nonce_length = 16;
    int wrzeszcz_nonce_length = 16;
    int reddye_key_length = 32;
    int bluedye_key_length = 32;
    int dark_key_length = 32;
    int wrzeszcz_key_length = 32;
    int mac_length = 16;
    unsigned char *mac_key[mac_length];
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
    fseek(infile, 0, SEEK_SET);
    unsigned char *msg;
    unsigned char *mac[mac_length];

    if (strcmp(algorithm, "reddye") == 0) {
        unsigned char *mac_key[reddye_key_length];
        unsigned char *key[reddye_key_length];
	//bluedye_kdf(password, key, kdf_salt, kdf_iterations, reddye_key_length);
	reddye_kdf(password, key, kdf_salt, kdf_iterations, reddye_key_length);
        if (strcmp(mode, encrypt_symbol) == 0) {
            outfile = fopen(outfile_name, "wb");
            unsigned char nonce[reddye_nonce_length];
            reddye_random(&nonce, reddye_nonce_length);
            fwrite(nonce, 1, reddye_nonce_length, outfile);
            msg = (unsigned char *) malloc(fsize);
            fread(msg, 1, fsize, infile);
            reddye_crypt(msg, key, nonce, fsize, reddye_key_length);
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
	    reddye_kdf(key, mac_key, kdf_salt, kdf_iterations, reddye_key_length);
	    //bluedye_kdf(key, mac_key, kdf_salt, kdf_iterations, reddye_key_length);
            h4a_mac(msg, fsize, mac, mac_key, reddye_key_length);
            fwrite(mac, 1, mac_length, outfile);
            fwrite(msg, 1, fsize, outfile);
            fclose(outfile);
            free(msg);
        }
        else if(strcmp(mode, decrypt_symbol) == 0) {
            unsigned char *mac_verify[mac_length];
            msg = (unsigned char *) malloc(fsize-mac_length);
	    reddye_kdf(key, mac_key, kdf_salt, kdf_iterations, reddye_key_length);
	    //bluedye_kdf(key, mac_key, kdf_salt, kdf_iterations, reddye_key_length);
            fread(mac, 1, mac_length, infile);
            fread(msg, 1, (fsize-mac_length), infile);
            h4a_mac(msg, (fsize-mac_length), mac_verify, mac_key, reddye_key_length);
            free(msg);
            if (memcmp(mac, mac_verify, mac_length) == 0) {
                msg = (unsigned char *) malloc(fsize-mac_length-reddye_nonce_length);
                unsigned char *nonce[reddye_nonce_length];
                fseek(infile, mac_length, SEEK_SET);
                fread(nonce, 1, reddye_nonce_length, infile);
                fread(msg, 1, (fsize - mac_length - reddye_nonce_length), infile);
                fclose(infile);
                reddye_crypt(msg, key, nonce, (fsize - mac_length - reddye_nonce_length), reddye_key_length);
                outfile = fopen(outfile_name, "wb");
                fwrite(msg, 1, (fsize - mac_length - reddye_nonce_length), outfile);
                fclose(outfile);
                free(msg);
            }
            else {
                printf("Error: Message has been tampered.\n");
            }
        }
    }
    else if (strcmp(algorithm, "wrzeszcz") == 0) {
        unsigned char *mac_key[wrzeszcz_key_length];
        unsigned char *key[wrzeszcz_key_length];
	reddye_kdf(password, key, kdf_salt, kdf_iterations, wrzeszcz_key_length);
        if (strcmp(mode, encrypt_symbol) == 0) {
            outfile = fopen(outfile_name, "wb");
            unsigned char nonce[wrzeszcz_nonce_length];
            reddye_random(&nonce, wrzeszcz_nonce_length);
            fwrite(nonce, 1, wrzeszcz_nonce_length, outfile);
            msg = (unsigned char *) malloc(fsize);
            fread(msg, 1, fsize, infile);
            wrzeszcz_crypt(msg, key, nonce, fsize, wrzeszcz_key_length);
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
	    reddye_kdf(key, mac_key, kdf_salt, kdf_iterations, wrzeszcz_key_length);
            h4a_mac(msg, fsize, mac, mac_key, wrzeszcz_key_length);
            fwrite(mac, 1, mac_length, outfile);
            fwrite(msg, 1, fsize, outfile);
            fclose(outfile);
            free(msg);
        }
        else if(strcmp(mode, decrypt_symbol) == 0) {
            unsigned char *mac_verify[mac_length];
            msg = (unsigned char *) malloc(fsize-mac_length);
	    reddye_kdf(key, mac_key, kdf_salt, kdf_iterations, wrzeszcz_key_length);
            fread(mac, 1, mac_length, infile);
            fread(msg, 1, (fsize-mac_length), infile);
            h4a_mac(msg, (fsize-mac_length), mac_verify, mac_key, wrzeszcz_key_length);
            free(msg);
            if (memcmp(mac, mac_verify, mac_length) == 0) {
                msg = (unsigned char *) malloc(fsize-mac_length-wrzeszcz_nonce_length);
                unsigned char *nonce[wrzeszcz_nonce_length];
                fseek(infile, mac_length, SEEK_SET);
                fread(nonce, 1, wrzeszcz_nonce_length, infile);
                fread(msg, 1, (fsize - mac_length - wrzeszcz_nonce_length), infile);
                fclose(infile);
                wrzeszcz_crypt(msg, key, nonce, (fsize - mac_length - wrzeszcz_nonce_length), wrzeszcz_key_length);
                outfile = fopen(outfile_name, "wb");
                fwrite(msg, 1, (fsize - mac_length - wrzeszcz_nonce_length), outfile);
                fclose(outfile);
                free(msg);
            }
            else {
                printf("Error: Message has been tampered.\n");
            }
        }
    }
    else if (strcmp(algorithm, "bluedye") == 0) {
        unsigned char *mac_key[reddye_key_length];
        unsigned char *key[bluedye_key_length];
	reddye_kdf(password, key, kdf_salt, kdf_iterations, bluedye_key_length);
        if (strcmp(mode, encrypt_symbol) == 0) {
            outfile = fopen(outfile_name, "wb");
            unsigned char nonce[bluedye_nonce_length];
            reddye_random(&nonce, bluedye_nonce_length);
            fwrite(nonce, 1, bluedye_nonce_length, outfile);
            msg = (unsigned char *) malloc(fsize);
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
	    reddye_kdf(key, mac_key, kdf_salt, kdf_iterations, bluedye_key_length);
            h4a_mac(msg, fsize, mac, mac_key, bluedye_key_length);
            fwrite(mac, 1, mac_length, outfile);
            fwrite(msg, 1, fsize, outfile);
            fclose(outfile);
            free(msg);
        }
        else if(strcmp(mode, decrypt_symbol) == 0) {
            unsigned char *mac_verify[bluedye_key_length];
            msg = (unsigned char *) malloc(fsize-mac_length);
	    reddye_kdf(key, mac_key, kdf_salt, kdf_iterations, bluedye_key_length);
            fread(mac, 1, mac_length, infile);
            fread(msg, 1, (fsize-mac_length), infile);
            h4a_mac(msg, (fsize-mac_length), mac_verify, mac_key, bluedye_key_length);
            free(msg);
            if (memcmp(mac, mac_verify, mac_length) == 0) {
                msg = (unsigned char *) malloc(fsize-mac_length-bluedye_nonce_length);
                unsigned char *nonce[bluedye_nonce_length];
                fseek(infile, mac_length, SEEK_SET);
                fread(nonce, 1, bluedye_nonce_length, infile);
                fread(msg, 1, (fsize - mac_length - bluedye_nonce_length), infile);
                fclose(infile);
                bluedye_crypt(msg, key, nonce, (fsize - mac_length - bluedye_nonce_length));
                outfile = fopen(outfile_name, "wb");
                fwrite(msg, 1, (fsize - mac_length - bluedye_nonce_length), outfile);
                fclose(outfile);
                free(msg);
            }
            else {
                printf("Error: Message has been tampered.\n");
            }
        }
    }
    else if (strcmp(algorithm, "dark") == 0) {
        unsigned char *mac_key[dark_key_length];
        unsigned char *key[dark_key_length];
	reddye_kdf(password, key, kdf_salt, kdf_iterations, dark_key_length);
        if (strcmp(mode, encrypt_symbol) == 0) {
            outfile = fopen(outfile_name, "wb");
            unsigned char nonce[dark_nonce_length];
            reddye_random(&nonce, dark_nonce_length);
            fwrite(nonce, 1, dark_nonce_length, outfile);
            msg = (unsigned char *) malloc(fsize);
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
	    reddye_kdf(key, mac_key, kdf_salt, kdf_iterations, dark_key_length);
            h4a_mac(msg, fsize, mac, mac_key, dark_key_length);
            fwrite(mac, 1, mac_length, outfile);
            fwrite(msg, 1, fsize, outfile);
            fclose(outfile);
            free(msg);
        }
        else if(strcmp(mode, decrypt_symbol) == 0) {
            unsigned char *mac_verify[mac_length];
            msg = (unsigned char *) malloc(fsize-mac_length);
	    reddye_kdf(key, mac_key, kdf_salt, kdf_iterations, dark_key_length);
            fread(mac, 1, mac_length, infile);
            fread(msg, 1, (fsize-mac_length), infile);
            h4a_mac(msg, (fsize-mac_length), mac_verify, mac_key, dark_key_length);
            free(msg);
            if (memcmp(mac, mac_verify, mac_length) == 0) {
                msg = (unsigned char *) malloc(fsize-mac_length-dark_nonce_length);
                unsigned char *nonce[dark_nonce_length];
                fseek(infile, mac_length, SEEK_SET);
                fread(nonce, 1, dark_nonce_length, infile);
                fread(msg, 1, (fsize - mac_length - dark_nonce_length), infile);
                fclose(infile);
                crypt(msg, key, nonce, (fsize - mac_length - dark_nonce_length));
                outfile = fopen(outfile_name, "wb");
                fwrite(msg, 1, (fsize - mac_length - dark_nonce_length), outfile);
                fclose(outfile);
                free(msg);
            }
            else {
                printf("Error: Message has been tampered.\n");
            }
        }
    }
}
