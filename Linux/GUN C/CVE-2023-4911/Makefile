CC = gcc
TARGET = run

.PHONY : run

run : exp libc.so.6
	./exp

exp : exp.c
	$(CC) -o exp exp.c

libc.so.6 : gen_libc.py
	python3 gen_libc.py

clean :
	rm -rf "\"" exp libc.so.6
