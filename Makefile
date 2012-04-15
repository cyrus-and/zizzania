# VARIABLES ]-------------------------------------------------------------------

CC      = gcc
CFLAGS  = -std=gnu99 -Wall -pedantic `pcap-config --cflags` `pkg-config --cflags glib-2.0`
LDFLAGS = `pcap-config --libs` `pkg-config --libs glib-2.0` -lpthread

# CONFIGURATIONS ]--------------------------------------------------------------

release debug: zizzania

release: CFLAGS += -O3
debug:   CFLAGS += -g -DDEBUG

# EXE ]-------------------------------------------------------------------------

zizzania: dispatcher.o dissectors.o handshake.o main.o zizzania.o

# UTILS ]-----------------------------------------------------------------------

.PHONY: clean cleanall

clean:
	rm -fr *.o

cleanall: clean
	rm -fr ./zizzania

# DEPENDENCIES ]----------------------------------------------------------------

dispatcher.o: dispatcher.c debug.h zizzania.h dissectors.h dispatcher.h
dissectors.o: dissectors.c dissectors.h
handshake.o: handshake.c debug.h dispatcher.h handshake.h zizzania.h \
 dissectors.h
main.o: main.c zizzania.h dissectors.h
zizzania.o: zizzania.c debug.h handshake.h zizzania.h dissectors.h \
 dispatcher.h
