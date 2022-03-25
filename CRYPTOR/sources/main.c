#include "encrypt.h"

#include <stdio.h>
#include <string.h>

#ifdef __unix__ 
    #include <sys/mman.h> 
#elif _WIN32
    #include <windows.h>
#else 
    #error "platform not supported"
#endif

static void *vmalloc(int size);
static int vfree(void *mem, int size);

typedef int (*payload_t)(
    FILE *(*_fopen) (const char *, const char *),
    int (*_fprintf) (FILE *, const char *, ...),
    int (*_fclose) (FILE *),
    int x
);

int main(void) {
    FILE *payload;
    void *exec;

    char buff[BUFSIZ];

    payload = fopen("payload.bin", "rb");
    if (payload == NULL) {
        return 1;
    }

    exec = vmalloc(BUFSIZ);

    fread(buff, sizeof(char), BUFSIZ, payload);
    fclose(payload);

    char key[] = "it's a key!";
    int lenkey = strlen(key);

    // decrypt
    encrypt_xor(exec, buff, BUFSIZ, key, lenkey);

    // exec
    printf("%d\n", ((payload_t)exec)(fopen, fprintf, fclose, 42131));
    vfree(exec, BUFSIZ);

    return 0;
}

static void *vmalloc(int size) {
    #ifdef __unix__ 
        return mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, 
            MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    #elif _WIN32
        return VirtualAlloc(0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    #endif
}

static int vfree(void *mem, int size) {
    #ifdef __unix__ 
        return munmap(mem, size);
    #elif _WIN32
        return VirtualFree(mem, size, MEM_RELEASE);
    #endif
}
