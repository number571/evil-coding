# CC=gcc -O0 -m32
# .PHONY:default build run
# default: build run
# build: main.c builder.c $(CFILES)
# 	$(CC) -o builder builder.c $(CFILES)
# 	$(CC) -o main main.c $(CFILES)
# run:
# 	./builder
# 	./main

CC=tcc32/tcc.exe
.PHONY:default build run
default: build run
build: main.c builder.c $(CFILES)
	wine $(CC) -o builder.exe builder.c $(CFILES)
	wine $(CC) -o main.exe main.c $(CFILES)
run:
	wine builder.exe
	wine main.exe
