CC=gcc

CFLAGS=-Wall -Werror -ggdb
LDFLAGS=-lpcap
NAME=bpfcountd

CONFDIR=/usr/local/etc/bpfcountd
SYSTEMDDIR=/usr/local/lib/systemd/system

ON_SYSTEMD=test -d /run/systemd/system &&

bpfcountd: main.o list.o usock.o filters.o util.o
	$(CC) ${LDFLAGS} main.o list.o usock.o filters.o util.o -o ${NAME}

all: test bpfcountd

install: bpfcountd
	install ${NAME} /usr/local/bin/${NAME}
	${ON_SYSTEMD} mkdir -p ${SYSTEMDDIR}
	${ON_SYSTEMD} cp dist/systemd@.service ${SYSTEMDDIR}/bpfcountd@.service
	mkdir -p ${CONFDIR}
	cp filters.example ${CONFDIR}/example.filters
	cp filters.example.extended ${CONFDIR}/example2.filters

uninstall:
	rm -f /usr/local/bin/${NAME}
	rm -f ${SYSTEMDDIR}/bpfcountd@.service
	rm -f ${CONFDIR}/example.filters
	rm -f ${CONFDIR}/example2.filters
	rmdir --ignore-fail-on-non-empty ${CONFDIR}

test: test_list.o list.o
	$(CC) ${LDFLAGS} test_list.o list.o -o test

clean:
	rm -f *.o
	rm -f ${NAME}
	rm -f test
