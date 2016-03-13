CC=gcc

CFLAGS=-Wall -Werror -ggdb
LDFLAGS=-lpcap
NAME=bpfcountd

bpfcountd: main.o list.o usock.o
	$(CC) ${LDFLAGS} main.o list.o usock.o -o ${NAME}

all: test bpfcountd

install: bpfcountd
	install ${NAME} /usr/local/bin/${NAME}

uninstall:
	rm -f /usr/local/bin/${NAME}

test: test_list.o list.o
	$(CC) ${LDFLAGS} test_list.o list.o -o test

clean:
	rm -f *.o
	rm -f ${NAME}
	rm -f test
