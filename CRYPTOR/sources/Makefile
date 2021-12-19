CC=tcc/tcc.exe
CFILES=crypto.c
.PHONY:default build run
default: build run
build: main.c builder.c $(CFILES)
	wine $(CC) -o builder.exe builder.c $(CFILES)
	wine $(CC) -o main.exe main.c $(CFILES)
run:
	wine builder.exe
	wine main.exe
