package main

import (
	"bufio"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
)

var (
	DBptr *DB
	PRIV  *rsa.PrivateKey
)

func init() {
	DBptr = DBInit("database.db")
	PRIV = ParsePrivate([]byte(PemPrivateKey))
	if DBptr == nil || PRIV == nil {
		panic("init error")
	}
}

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
3. size // number of users in DB
4. list // list of users in DB
5. info // user info by ID
6. allw // allow access mode by ID
7. deny // deny access mode by ID
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
		case "size":
			fmt.Printf("Size: %d\n\n", DBptr.Size())
		case "list":
			for i := 1; ; i++ {
				user := DBptr.GetUserByID(i)
				if user == nil {
					break
				}
				fmt.Printf("%d: %s\n", user.Id, user.Uid)
			}
			fmt.Println()
		case "info":
			if len(splited) != 2 {
				fmt.Println("error: not enough args")
				continue
			}
			id, err := strconv.Atoi(splited[1])
			if err != nil {
				fmt.Println("error: strconv")
				continue
			}
			user := DBptr.GetUserByID(id)
			if user == nil {
				fmt.Println("error: user undefined\n")
				continue
			}
			fmt.Printf(
				"\nID: %d\nUID: %s\nACCESS: %t\nPRIV_KEY: \n%s\n\n",
				user.Id,
				user.Uid,
				user.Access,
				user.PrvKey,
			)
		case "allw", "deny":
			var err error
			if len(splited) != 2 {
				fmt.Println("error: not enough args")
				continue
			}
			switch splited[0] {
			case "allw":
				err = DBptr.UpdateAccess(splited[1], true)
			case "deny":
				err = DBptr.UpdateAccess(splited[1], false)
			}
			if err != nil {
				fmt.Printf("error: %s\n\n", err.Error())
				continue
			}
			fmt.Println("access mode has been updated\n")
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
		Head string   `json:"head"`
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

	result := ""

	switch req.Head {
	case "/PUT":
		ok := putPage(req.Body)
		if !ok {
			response(w, 3, "error: put page")
			return
		}
		result = "success: action completed"

	case "/GET":
		priv, ok := getPage(req.Body)
		if !ok {
			response(w, 3, "error: get page")
			return
		}
		result = HexEncode(BytesPrivate(priv))

	default:
		response(w, 4, "error: page undefined")
		return
	}

	response(w, 0, result)
}

func getPage(body []string) (*rsa.PrivateKey, bool) {
	if len(body) != 1 {
		return nil, false
	}

	uid := body[0]

	priv := DBptr.GetKey(uid)
	if priv == nil {
		return nil, false
	}

	return priv, true
}

func putPage(body []string) bool {
	const (
		ASIZE = 256
		KSIZE = 32
	)

	if len(body) != 2 {
		return false
	}

	encSkey := HexDecode(body[0])
	if encSkey == nil {
		return false
	}

	encPkey := HexDecode(body[1])
	if encPkey == nil {
		return false
	}

	decSkey := DecryptRSA(PRIV, encSkey)
	if decSkey == nil {
		return false
	}

	decPkey := DecryptAES(decSkey, encPkey)
	if decPkey == nil {
		return false
	}

	priv := ParsePrivate(decPkey)
	if priv == nil {
		return false
	}

	if priv.N.BitLen() != ASIZE*8 {
		return false
	}

	uid := HashPublic(&priv.PublicKey)
	DBptr.SetKey(uid, priv)

	return true
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

const (
	PemPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIJKgIBAAKCAgEAtyGmMa66N4dSVSaT0bBKgGC7Bb6Jt6TXpXItRPADg2X/gQjj
8u8qVj+MIvjxi+J1sgiLMVlQPvBlgpmw3sKkDMiGRdKQtETu54Yw77ejZbk+WiIC
tbdnJYp33rWAUY1+FfXWh5C0WwcDQ5KKVHi2ij7+JctxMlp4jafWWDSZ1V5z7Cj7
WxW2RfymV+C1qWgVYptiIgXnnP8qAkxUGenCOLvz0zTUUZTJkSLBWdHyy6jSw20d
IwAUE+kTl9Rxmv28e99f7dRAs65s52djlDYObcYPxVNx2A9p/3D4oM+p+ySJEDlG
MTFZl/PTUgZZd34KNqXFwuy6OkmqIB750OoqjlD2qDQ3hM9dQQxBPYrumK03l5Wd
zw+LjA7a5l5M5ON7ieXjg6OonrYUlXXeteIIwOkByMXmxdvTlBhsOSW7OKO+XqhI
paKcwpCuosYmue8QbTeGCFTtsejcNwMSnbXY5QOt6u1E7C0JIE8vagePKaxj8pVC
EvXGVLXXeNZD2HKlocgeJwM6ZWcvEtrnGNh+EaT1dNKybmwYRyllGxPiEx/DjDYF
8WvdwofBmiQwEXnsBzHhUHduXhucuFTIQtTD3EbwazRnMH9yoa1a57JaKCN/j/Rh
P9aJpdIdlfX+NxNIwSf/IM5T3jS/IdwFbX2IIhzMOIATRzewnkgh6k6IcR8CAwEA
AQKCAgEAnc0JAFanb6HTeDw9s7pM+EJh5ZlB4lTQ3Wd9SqHm5RrHB9E5WuRrftZT
Uu9gdEE3WamzB1sGorVTQy5cEhd2dO11hkTjG/MqSaaAFJAQ5F6zM8eKvjrDTr36
fJW5dIyP0Sx9J2OxhZ6NWXS0bgV2hbmyFa8wY0tCBg5RzL/Gru0sxpqpvNsArV3/
mEmxP8DIbKen79lWsxnMgR50eb/L9EdA2wXyzjl/Vuiz40neBU/8DRnAuaAfrOhy
UapmGj/6YmMgrjbvaeUrQlr8m4HY/Q5mGIrG1n6xv8MA+tD2j8nzsV8o9MqpgR5B
QbTm8uhQtLYzqruB3SgMyJDogvTEpVgOfdrmriEpmgy2J46iiC6ucYXKtFqwsYkR
2+s8e1jmSuVn8fwBZQV0Rplu8f8y0+udSo1Xzkrap/jvee3wSvpTG7NVtyu6LxTg
UPQsnFRxwXXrPiR5to+bhg7RWTEOxSrUaWStlB+N3AZYfAf3FabOQdRoAoDE+ama
Ic16JLriziSvPH1PjBStdkV4X/eIjuxGb4kBKM4vaZ2i3CnXo1UjAOouOEeGMGj/
WWOc0OzmHg/x2rXT0g2TSOZyJGZc/hlqCqZtiGbARwSjnvN3DhSdBulL4//vbvEU
pQ/gPBneSl7TjnG9/IG2r50IeP77GwpAYD7N3RPHGU1YDt0GEsECggEBAOArEfcg
l9FNSRn6PEXXfKFedT8pi1DE5m7wxyxZeYmXURP3l5WaYQok/gbvX9cO+edyEkjr
foRxW4Pax5sLeSPeGHN5nZ+4XqMostj/c7qrDpeiMopN1WQWaIrq3gMeYpcLkIRD
C8fh81loAPIoE7t1kow0XxA8LeIzggGNe/hUqJxj4iB+xezElPI9XmYF3T40MPgU
nPuSc7R7a4k7XFQMN6811s0DNY6etsnfRI+8ZZq6r6gdKzcgl9yj3Pd42qEVkbVR
pVKKH+4/ZUqu/VFZ5V192El7z6zmX21shwbvrb77YqKSDoSlAVfFjsAXcKt5HgW6
7wm04rCAdjpb19MCggEBANEi0MPns/u+GicUUoUNuNqbAoy5jwt0haqiQbu5AGpP
/JDZERB4WZCxxrv5eZd7z+893ozIYZ84yu7Dei9JZuPxJZL8Bpcj85SswFySp6Vf
W+f3CZ3WPwv2RKYbT0Nt2gkBRxyi5JQk+8O/fmfkpgjZTUYd4deB1fXk+SdYGLXn
LnKRB5NwCe9wR+6d4YrD5fkQIDUPZO9zsaueGYZtWrtLl+vRJQC0pzu4p6VbjQG6
FJkSx1ydgKPVyF82vEiPkJQVglkBGFau7UnZKb1DzYdaYXw4Yy6HqIVNvhMLRM0E
YEU6zoC1KZeSah6GDaJUwmQJLrfJsZE5Sfzg5kGzngUCggEBAKMktV51igf5h0ow
o8zwlvOaGxps0cdmhY4YDdxpAdrxFUDC4L8wK4+GfJnvfIC3lYirrEMFoH4jQcck
YkCkiPVhncnsqJqlQ7ra0865mzAvbd9NXBrrqnG9HTh81jbO1lG3SOX5JYnDF6fp
2UZjhHjZiF4hf04BfiMx+VvH7IE+m7e1ucyMdt9p8jyaDSmS+wFaWokx903ft/WS
HSEy4m8ItT3+oOVzgHbba4xfwTYalpeVZmGjWOA2CE+7sgUpH3Q8jl63nOoFPFfY
K4++6v1Zv2PbQp24Tdw3jRvF8D9MD9b+fTpzsb03mVKXpNyIMqeY7hCdi3o0+wYZ
d/HhBaECggEAMkNi12KtsDhdQr0wpAfLQMb2kunaBk/H/F2o3Lw27FYzBoEVB9dU
92CyueTYo16/d+lvvng+di0JIN9cU1cZ4njHpg7qapLabQYj6VvZ7PYBObv21Ld0
SaSzlRSFNViGiZmEBM7ljvFgjQhOEhwzB3dqigqOh+QNj16rvxf+QGHCmQhgQMAx
sxlSQHgzh81TTUvh4b7EbIRq1CtYSSWpI9CkP6nxcbz5YHId4LEjL6IQZ0XLImg8
TaQI11FpaSsP/Xc577hCqDq8jv4hePp9wCUpvtgyhjFWgEtR/nO74mZF2P2sOeTQ
jTxEQvfG+RfT7IUEdGmGQrf5H0zSKkJIHQKCAQEAq9ukaQyrbIJuViQgugxKLFJH
0UNWod4PLqP2RNH/rIuVmOsjd4OhXKRU6jfMURkedgzaN3DWrN/YX6VEfqp5u4OC
6Lq0W3V/HXNe0FiGK3ZRXMH6zjMn2sHq/w/0M8YrSrRFSH+ExcaIoH2VxF9y/V1K
guF1bvRx1n/i6DM79AAYEx1uXs9lVElDchCJ49L0WlOc+aUcALLnrZr5wVQnesSE
+Juc765p+JT7rY1CQYnVaFnfAJl0lYQ0PFuCy56DpY2z8GMsZlHKNLHouU+p1ieH
3/hu5iQP3YYucXs9v575B/QZuppg20zlfzzDSXNx5rHvyz6GQjlJi0HW2EZxSg==
-----END RSA PRIVATE KEY-----
`
)
