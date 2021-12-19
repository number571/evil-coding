package main

import (
	"log"
	"fmt"
	"net/http"
)

func main() {
	fmt.Println("Server is listening...\n")
	http.HandleFunc("/", indexPage)
	http.ListenAndServe(":9090", nil)
}

func indexPage(w http.ResponseWriter, r *http.Request) {
	log.Printf("[M: %s] [U: %s] [A: %s]\n", r.Method, r.URL.Path, r.RemoteAddr)
	fmt.Fprint(w, "hello, world")
}
