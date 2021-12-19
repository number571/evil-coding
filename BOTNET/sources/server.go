package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	Target = "NULL"
)

func main() {
	fmt.Println("Server is listening...\n")
	go adminConsole()
	http.HandleFunc("/", indexPage)
	http.HandleFunc("/cmd", cmdPage)
	http.ListenAndServe(":8080", nil)
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
				fmt.Printf("target = '%s'\n\n", Target)
				continue
			}
			Target = splited[1]
			fmt.Println("target set\n")
		default:
			fmt.Println("error: command undefined\n")
		}
	}
}

func inputString(begin string) string {
	fmt.Print(begin)
	msg, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.Replace(msg, "\n", "", 1)
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
