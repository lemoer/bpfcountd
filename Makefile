CC=gcc

CFLAGS=-Wall -Werror -ggdb
LDFLAGS=-lpcap
NAME=app

app: main.o list.o usock.o
	$(CC) ${LDFLAGS} main.o list.o usock.o -o ${NAME}

all: test app

test: test_list.o list.o
	$(CC) ${LDFLAGS} test_list.o list.o -o test

clean:
	rm -f *.o
	rm -f ${NAME}
	rm -f test
