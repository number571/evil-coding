#include <stdio.h>
#include <string.h>

#include "payload.h"

int main(void) {
	FILE *payload;
	int nbytes;

	payload = fopen("payload.bin", "wb");
	if (payload == NULL) {
		return 1;
	}

	nbytes = (unsigned long)_end - (unsigned long)_payload;

	fwrite((char *) _payload, sizeof(char), nbytes, payload);
	fclose(payload);

	return 0;
}
