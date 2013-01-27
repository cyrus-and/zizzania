# VARIABLES ]-------------------------------------------------------------------

CC      = gcc
CFLAGS  = -std=gnu99 -Wall -pedantic `pcap-config --cflags` `pkg-config --cflags glib-2.0`
LDFLAGS = `pcap-config --libs` `pkg-config --libs glib-2.0` -lpthread

# CONFIGURATIONS ]--------------------------------------------------------------

release debug vdebug: zizzania

release: CFLAGS += -O3 -Os
debug:   CFLAGS += -g -DDEBUG
vdebug:  CFLAGS += -g -DDEBUG -DVDEBUG

# EXE ]-------------------------------------------------------------------------

zizzania: dispatcher.o dissectors.o handshake.o killer.o main.o zizzania.o

# UTILS ]-----------------------------------------------------------------------

.PHONY: clean cleanall install uninstall

clean:
	rm -fr *.o

cleanall: clean
	rm -fr ./zizzania

install:
	cp ./zizzania /usr/bin

uninstall:
	rm -f /usr/bin/zizzania

# DEPENDENCIES ]----------------------------------------------------------------

dispatcher.o: dispatcher.c debug.h zizzania.h dissectors.h killer.h \
 dispatcher.h
dissectors.o: dissectors.c dissectors.h
handshake.o: handshake.c debug.h killer.h zizzania.h dissectors.h \
 handshake.h
killer.o: killer.c debug.h killer.h zizzania.h dissectors.h
main.o: main.c zizzania.h dissectors.h
zizzania.o: zizzania.c debug.h handshake.h zizzania.h dissectors.h \
 dispatcher.h
