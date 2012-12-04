# Makefile for fulltrace
# Compiler: gcc
# Linker: ld

CC = gcc
CFLAGS = -Wall -O3 -finline-functions
INCDIR="."

WRAPPER_SOURCES = wrapper.c
WRAPPER_OBJECTS = wrapper.o

%.o : %.c
	@$(CC) $(CFLAGS) -I$(INCDIR) -c $<

build: wrapper

wrapper: $(WRAPPER_OBJECTS)
	$(CC) $(CFLAGS) $(WRAPPER_OBJECTS) -o $@

.PHONY: clean

clean:
	rm -rf $(WRAPPER_OBJECTS) \
	wrapper
