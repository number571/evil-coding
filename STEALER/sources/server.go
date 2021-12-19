package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

const (
	MAXSIZE = (6 * (5 << 20) + 256)
	ROOTDIR = "./saves/"
)

func init() {
	os.Mkdir(ROOTDIR, 0700)
}

func main() {
	fmt.Println("Server is listening...\n")
	http.HandleFunc("/", indexPage)
	http.HandleFunc("/cmd", cmdPage)
	http.ListenAndServe(":8080", nil)
}

func indexPage(w http.ResponseWriter, r *http.Request) {
	response(w, 0, "success: action completed")
}

func cmdPage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OS    int      `json:"os"`
		Name  string   `json:"name"`
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
