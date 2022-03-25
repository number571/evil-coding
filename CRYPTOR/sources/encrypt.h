#ifndef ENCRYPT_H
#define ENCRYPT_H

void encrypt_xor(char *output, char *input, int isize, char *key, int ksize) {
    for (int i = 0; i < isize; ++i) {
        output[i] = input[i] ^ key[i % ksize];
    }
}

#endif 
