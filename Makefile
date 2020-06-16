CC = gcc 
FLAGS = -Wall

PHONY: all

all:
	$(CC) $(FLAGS) present.c main.c -o PRESENT

clean:
	rm -rf *.o PRESENT
    