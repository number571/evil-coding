#include <stdio.h>
#include <string.h>

#include "crypto.h"

int main(void) {
	int (*_Begin)
		(FILE* (*) (const char *, const char *),
		size_t (*) (const void *, size_t, size_t, FILE *),
		int (*) (FILE *),
		char *data,
		int size
	);
	char buff[BUFSIZ];

	FILE *payload = fopen("payload.bin", "rb");
	if (payload == NULL) {
		return 1;
	}
	int nbytes = fread(buff, sizeof(char), BUFSIZ, payload);
	fclose(payload);

	char key[] = "it's a key!";
	char iv[] = "init vector!";

	// DECRYPT
	crypto_encrypt(buff, key, strlen(key), iv, strlen(iv), buff, nbytes);

	char msg[] = "some file data";
	int size = strlen(msg);

	_Begin = (int (*)
		(FILE* (*) (const char *, const char *),
		size_t (*) (const void *, size_t, size_t, FILE *),
		int (*) (FILE *),
		char *data,
		int size)
	) &buff[0];
	_Begin(fopen, fwrite, fclose, msg, size);

	return 0;
}
