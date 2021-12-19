CC=gcc
CFLAGS=-Wall -std=c99
CFILES=encrypter.c enckernel.c extclib/extclib.o

GC=go build
GFILES=server.go crypto.go database.go

.PHONY: default install build
default: install build
install:
	git clone https://github.com/number571/extclib.git
	make -C extclib/
build: $(CFILES) $(GFILES)
	$(CC) -o encrypter  $(CFILES) $(CFLAGS) -lcrypto
	$(GC) -o server $(GFILES) 
clean:
	rm -rf extclib/
	rm -f encrypter server database.db
