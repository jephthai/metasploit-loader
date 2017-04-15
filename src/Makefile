#
# This Makefile is designed to work on a Windows system with MINGW
# installed. (i.e., it works on my Windows dev box, anyway...).  It
# will require modification (namely, the CC variable) to compile
# correctly on a linux box with a cross-compiler.
#
#

CC=gcc
CFLAGS=-O2 -s -lws2_32 -mwindows
DEL=cmd /c del

default: loader.exe loader64.exe

loader.exe: main.c
	$(CC) -o loader.exe main.c $(CFLAGS)

loader64.exe: main.c
	$(CC) -m64 -o loader64.exe main.c $(CFLAGS)

clean:
	$(DEL) loader.exe
	$(DEL) loader64.exe
