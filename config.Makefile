.PHONY: cleanup

Makefile:
	wget -q https://raw.githubusercontent.com/cyrus-and/dry-makefile/master/Makefile

SOURCES        := $(wildcard src/*.c)
EXECUTABLES    := src/zizzania.c
COMPILER_FLAGS := -Wall -isystem external/
LINKER_FLAGS   := -pthread
LIBRARIES      := -lpcap
BUILD_PROFILES := release debug
SETUP_HOOK     := external/uthash.h
CLEANUP_HOOK   := cleanup

release: COMPILER_FLAGS += -O3 -Os
debug:   COMPILER_FLAGS += -ggdb3 -Werror -pedantic -DDEBUG

external/uthash.h:
	wget -q -P external/ https://raw.githubusercontent.com/troydhanson/uthash/v2.1.0/src/uthash.h

cleanup:
	$(RM) -r Makefile external/
