#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/epoll.h> // for epoll_ctl(), struct epoll_event
#include <errno.h>


#include "usock.h"

int usock_prepare(const char *path, const int epoll_fd) {
	int sock;
	struct sockaddr_un local;
	struct epoll_event event;
	
	if ((sock = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0)) == -1) {
		perror("socket");
		exit(1);
	}

	local.sun_family = AF_UNIX;
	strncpy(local.sun_path, path, sizeof(local.sun_path) -1);

	// remove the unix socket if it exists
	unlink(local.sun_path);

	if (bind(sock, (struct sockaddr*) &local, sizeof(struct sockaddr_un))) {
		perror("bind");
		exit(1);
	}

  // allow access to all users
  chmod(local.sun_path, S_IRWXU | S_IRWXG | S_IRWXO);

	if(listen(sock, 5) == -1) {
		perror("listen");
		exit(1);
	}

	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN;
	event.data.ptr = NULL;

	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &event)) {
		fprintf(stderr, "Can't add pcap to epoll.\n");
		exit(1);
	}

	return sock;
}

int usock_accept(int sock) {
	return accept(sock, NULL, NULL);
}

void usock_sendstr(int client_sock, const char* str) {
	if(send(client_sock, str, strlen(str), MSG_NOSIGNAL) == -1) {
		if(errno == EPIPE) {
			fprintf(stderr, "warning: usock client closed connection before sending data was possible\n");
		} else {
			perror("send");
			exit(1);
		}
	}
}

void usock_finish(int sock) {
	close(sock);
}
		
