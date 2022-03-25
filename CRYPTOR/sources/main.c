#include <stdio.h>

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
	FILE* (*fopen) (const char *, const char *),
	int (*fprintf) (FILE*, const char *, ...),
	int (*fclose) (FILE *),
	int x
);

int main(void) {
	FILE *payload;
	void *buff; 
	
	payload = fopen("payload.bin", "rb");
	if (payload == NULL) {
		return 1;
	}

	buff = vmalloc(BUFSIZ);

	fread(buff, sizeof(char), BUFSIZ, payload);
	fclose(payload);

	printf("%d\n", ((payload_t) buff)(fopen, fprintf, fclose, 20));
	vfree(buff, BUFSIZ);

	return 0;
}

static void *vmalloc(int size) {
	#ifdef __unix__ 
		return mmap(NULL, size, PROT_EXEC | PROT_READ | PROT_WRITE, 
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
