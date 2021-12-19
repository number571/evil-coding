#include <stdio.h>
#include <string.h>

#include "crypto.h"

#include "payload.h"

int main(void) {
	int nbytes = (unsigned long)_end - (unsigned long)_payload;
	char buff[nbytes];

	for (int i = 0; i < nbytes; ++i) {
		buff[i] = ((char *) _payload)[i];
	}

	char key[] = "it's a key!";
	char iv[] = "init vector!";

	// ENCRYPT
	crypto_encrypt(buff, key, strlen(key), iv, strlen(iv), buff, nbytes);

	FILE *payload = fopen("payload.bin", "wb");
	if (payload == NULL) {
		return 1;
	}
	fwrite(buff, sizeof(char), nbytes, payload);
	fclose(payload);

	return 0;
}
