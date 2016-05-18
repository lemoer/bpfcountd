CC=gcc

CFLAGS=-Wall -Werror -ggdb
LDFLAGS=-lpcap
NAME=bpfcountd
PREFIX?=/usr/local

CONFDIR?=${PREFIX}/etc/bpfcountd

bpfcountd: main.o list.o usock.o filters.o util.o
	$(CC) ${LDFLAGS} main.o list.o usock.o filters.o util.o -o ${NAME}

all: test bpfcountd

install: bpfcountd
	cp filters.example ${CONFDIR}/example.filters
	cp filters.example.extended ${CONFDIR}/example2.filters
	install -Dm 755 ${NAME} ${PREFIX}/sbin/${NAME}

uninstall:
	rm -f ${CONFDIR}/example.filters
	rm -f ${CONFDIR}/example2.filters
	rmdir --ignore-fail-on-non-empty ${CONFDIR}
	rm -f ${PREFIX}/sbin/${NAME}

test: test_list.o list.o
	$(CC) ${LDFLAGS} test_list.o list.o -o test

clean:
	rm -f *.o
	rm -f ${NAME}
	rm -f test
