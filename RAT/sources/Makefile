CC=gcc
CFLAGS=-Wall -std=gnu99
CFILES=bot.c extclib/extclib.o

GC=go build
GFILES=server.go

.PHONY: default install build
default: install build
install:
	git clone https://github.com/number571/extclib.git
	make -C extclib/
build: $(CFILES) $(GFILES)
	$(CC) -o bot $(CFILES) $(CFLAGS) -lcrypto
	$(GC) -o server $(GFILES) 
clean:
	rm -rf extclib/
	rm -f bot server
