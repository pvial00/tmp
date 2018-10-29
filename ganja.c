#include <string.h>
#include <stdint.h>
#include <stdio.h>

uint32_t conv8to32(unsigned char buf[]) {
    int i;
    uint32_t output;

    output = (buf[0] << 24) + (buf[1] << 16) + (buf[2] << 8) + buf[3];
    return output;
}

unsigned char * digest(unsigned char * data, long datalen, unsigned char * D) {
    int rounds = 20 * 8;
    uint32_t H[8] = {0};
    //uint32_t block[8];
    unsigned char temp[4];
    uint32_t temp32[8];
    uint32_t m = 0x00000001;
    int b, i, f;
    int c = 0;
    int blocks = datalen / 32;
    int blocks_extra = datalen % 32;
    int blocksize = 32;
    if (blocks_extra != 0) {
        blocks += 1;
    }
    //unsigned char padding[blocks_extra] = {blocks_extra};

    for (int b = 0; b < blocks; b++) {
	for (int i = 0; i < (blocksize / 4); i++) {
	    uint32_t block[8] = {0};
            for (int f = 0; f < 4; f++) {
	        temp[f] = data[c];
	        c += 1;
		block[i % 8] = conv8to32(temp);
		H[i % 8] ^= block[i % 8] ^ m;
		H[(i+1) % 8] ^= H[i % 8];
	    }
	    for (int r = 0; r < 8; r++) {
	        H[r] = (H[r] ^ block[r] ^ m);
		m ^= H[r];
		H[r] ^= (H[r] << 2);
	    }
	}
    }
    for (int r = 0; r < rounds; r++) {
        H[r % 8] = (((H[r % 8]+ m + H[(r+1) % 8]) & 0xFFFFFFFF) ^ H[(r+2) % 8] ^ H[(r+3) % 8] ^ H[(r+4) % 8] ^ H[(r+5) % 8] ^ H[(r+6) % 8] ^ H[(r+7) % 8]);
	m = (m + H[r % 8]) & 0xFFFFFFFF;
	H[r % 8] ^= H[(r+4) % 8];
    }

	    
    c = 0;
    for (i = 0; i < 8; i++) {
        D[c] = (H[i] & 0xFF000000) >> 24;
        D[c+1] = (H[i] & 0x00FF0000) >> 16;
	D[c+2] = (H[i] & 0x0000FF00) >> 8;
	D[c+3] = (H[i] & 0x000000FF);
	c = (c + 4);
    }
}

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

    digest(data, fsize, d);
    for (int x = 0; x < 32; x++) {
        sprintf(&hex_out[x*2], "%02X", d[x]);
    }
    printf("%s\n", hex_out);
}
