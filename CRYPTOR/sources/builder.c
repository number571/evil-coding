#include "payload.h"
#include "encrypt.h"

#include <stdio.h>
#include <string.h>

int main(void) {
    FILE *payload;
    int nbytes;

    payload = fopen("payload.bin", "wb");
    if (payload == NULL) {
        return 1;
    }

    nbytes = (unsigned long)_end - (unsigned long)_payload;
    char buff[nbytes];

    char key[] = "it's a key!";
    int lenkey = strlen(key);

    // encrypt
    encrypt_xor(buff, (char*)_payload, nbytes, key, lenkey);

    fwrite(buff, sizeof(char), nbytes, payload);
    fclose(payload);

    return 0;
}
