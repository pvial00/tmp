#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "reddye_kdf.c"

int rounds = 16;
int keylen = 16;
int j = 0;
int temp[32] = {0};
int last[32] = {0};
int next[32] = {0};
int S[256];
uint32_t K[16] = {0};

void gen_subkeys(unsigned char * key, int keylen, int rounds) {
    int a, b, c, d, i;
    uint32_t keytemp[(keylen /4)];
    uint32_t temp = 0x00000001;
    for (i = 0; i < (keylen / 4); i++) {
        keytemp[i] = (key[a] << 24) + (key[b] << 16) + (key[c] << 8) + key[d];
	a += 4;
	b += 4;
	c += 4;
	d += 4;
    }
    temp = (keytemp[0] + keytemp[1] + keytemp[2] + keytemp[3] + temp) & 0xFFFFFFFF;
    for (i = 0; i < rounds; i++) {
        temp = (keytemp[0] + keytemp[1] + keytemp[2] + keytemp[3] + temp) & 0xFFFFFFFF;
	K[i] = temp;
    }

}

void gen_sbox(unsigned char * key, int keylen) {
    int i;
    int j;
    int temp;
    for (i = 0; i < 256; i++) {
        S[i] = i;
    }
    for (i = 0; i < 256; i++) {
	j = (j + key[i % keylen]) & 0xFF;
	temp = S[i];
        S[i] = S[j];
	S[j] = temp;
    }
    //for (i = 0; i < 256; i++) {
    //    printf("%d ", S[i]);
    //}
}

uint32_t F(uint32_t xr) {
    int v, x, y, z;
    v = (xr & 0xFF000000) >> 24;
    x = (xr & 0x00FF0000) >> 16;
    y = (xr & 0x0000FF00) >> 8;
    z = (xr & 0x000000FF);

    v = v ^ S[0];
    x = x ^ S[0];
    y = y ^ S[0];
    z = z ^ S[0];

    //v = v ^ y;
    //x = x ^ z;
    //z = z ^ v;
    //y = y ^ x;
    xr = (v << 24) + (x << 16) + (y << 8) + z;
    return xr;
}

uint32_t block_encrypt(uint32_t *xl, uint32_t *xr) {
    int i;
    uint32_t temp;
    uint32_t Xl;
    uint32_t Xr;

    Xl = *xl;
    Xr = *xr;
    for (i = 0; i < rounds; i++) {
	//printf("%ul ", Xl);
        Xl = Xl ^ K[i];
	//printf("%ul ", Xl);
        //Xr = Xr ^ F(Xr);

	temp = Xl;
	Xl = Xr;
	Xr = temp;

    }
    //temp = Xl;
    //Xl = Xr;
    //Xr = temp;
    *xl = Xl;
    *xr = Xr;
}

uint32_t block_decrypt(uint32_t *xl, uint32_t *xr) {
    int i;
    uint32_t temp;
    uint32_t Xl;
    uint32_t Xr;

    Xl = *xl;
    Xr = *xr;
    for (i = (rounds - 1); i != -1; i--) {
	//printf("%d ", i);
	//printf("%ul ", Xl);
        Xl = Xl ^ K[i];
	//printf("%ul ", Xl);
        //Xr = Xr ^ F(Xr);

	temp = Xl;
	Xl = Xr;
	Xr = temp;

    }
    //temp = Xl;
    //Xl = Xr;
    //Xr = temp;
    *xl = Xl;
    *xr = Xr;
}
    
    


void usage() {
    printf("blackdye-cbc <encrypt/decrypt> <input file> <output file> <password>\n");
    exit(0);
}

int main(int argc, char *argv[]) {
    FILE *infile, *outfile, *randfile;
    char *in, *out, *mode;
    unsigned char *data = NULL;
    unsigned char *buf = NULL;
    int x = 0;
    int ch;
    int buflen = 8;
    int bsize = 8;
    int iterations = 10000;
    unsigned char *key[keylen];
    unsigned char *password;
    int nonce_length = 16;
    unsigned char nonce[nonce_length];
    unsigned char block[buflen];
    uint32_t xl;
    uint32_t xr;
    if (argc != 5) {
        usage();
    }
    mode = argv[1];
    in = argv[2];
    out = argv[3];
    password = argv[4];
    infile = fopen(in, "rb");
    fseek(infile, 0, SEEK_END);
    long fsize = ftell(infile);
    fseek(infile, 0, SEEK_SET);
    outfile = fopen(out, "wb");
    int c = 0;
    int b = 0;
    int m = 0;
    if (strcmp(mode, "encrypt") == 0) {
        long blocks = fsize / buflen;
        long extra = fsize % buflen;
        if (extra != 0) {
            blocks += 1;
        }
        randfile = fopen("/dev/urandom", "rb");
        fread(&nonce, nonce_length, 1, randfile);
        fclose(randfile);
        fwrite(nonce, 1, nonce_length, outfile);
	unsigned char salt[] = "BlackDyeCipher";
	kdf(password, key, salt, iterations, keylen);
	gen_subkeys(key, keylen, rounds);
	gen_sbox(key, keylen);
	for (int b = 0; b < blocks; b++) {
            fread(block, 1, bsize, infile);
	    xl = (block[0] << 24) + (block[1] << 16) + (block[2] << 8) + block[3];
	    xr = (block[4] << 24) + (block[5] << 16) + (block[6] << 8) + block[7];
	    //printf("%ul %ul", xl, xr);
	    block_encrypt(&xl, &xr);
	    //printf("%ul %ul", xl, xr);
	    //exit(0);
	    block[0] = (xl & 0xFF000000) >> 24;
	    block[1] = (xl & 0x00FF0000) >> 16;
	    block[2] = (xl & 0x0000FF00) >> 8;
	    block[3] = (xl & 0x000000FF);
	    block[4] = (xr & 0xFF000000) >> 24;
	    block[5] = (xr & 0x00FF0000) >> 16;
	    block[6] = (xr & 0x0000FF00) >> 8;
	    block[7] = (xr & 0x000000FF);
            fwrite(block, 1, bsize, outfile);
	}
    }
    else if (strcmp(mode, "decrypt") == 0) {
        long blocks = (fsize - nonce_length) / buflen;
        long extra = (fsize - nonce_length) % buflen;
        if (extra != 0) {
            blocks += 1;
        }
        fread(nonce, 1, nonce_length, infile);
	unsigned char salt[] = "BlackDyeCipher";
	kdf(password, key, salt, iterations, keylen);
	gen_subkeys(key, keylen, rounds);
	gen_sbox(key, keylen);
        for (int d = 0; d < blocks; d++) {
            fread(block, buflen, 1, infile);
	    xl = (block[0] << 24) + (block[1] << 16) + (block[2] << 8) + block[3];
	    xr = (block[4] << 24) + (block[5] << 16) + (block[6] << 8) + block[7];
	    block_decrypt(&xl, &xr);
	    block[0] = (xl & 0xFF000000) >> 24;
	    block[1] = (xl & 0x00FF0000) >> 16;
	    block[2] = (xl & 0x0000FF00) >> 8;
	    block[3] = (xl & 0x000000FF);
	    block[4] = (xr & 0xFF000000) >> 24;
	    block[5] = (xr & 0x00FF0000) >> 16;
	    block[6] = (xr & 0x0000FF00) >> 8;
	    block[7] = (xr & 0x000000FF);
            fwrite(block, 1, bsize, outfile);
            //if ((d == (blocks - 1)) && extra != 0) {
            //    bsize = extra;
            //}
            //bsize = sizeof(block);
	    //for (m = 0; m < bsize; m++) {
	    //    next[m] = block[m]; }
            //for (b = 0; b < bsize; b++) {
            //    block[b] = block[b] ^ last[b];
            //}
	    //for (m = 0; m < bsize; m++) {
	    //    last[m] = next[m]; }
            if (d == (blocks - 1)) {
		int count = 0;
		int padcheck = block[31];
		int g = 31;
		for (m = 0; m < padcheck; m++) {
		    if ((int)block[g] == padcheck) {
		        count += 1;
		    }
		    g = (g - 1);
		}
		if (count == padcheck) {
		    bsize = (keylen - count);
		}
            }
            fwrite(block, 1, bsize, outfile);
        }
    }
    fclose(infile);
    fclose(outfile);
    return 0;
}
