#ifndef __USOCK__H
#define __USOCK__H

#include <sys/socket.h>
#include <sys/un.h>

int usock_prepare(const char* path);
int usock_accept(int sock);
void usock_finish(int sock);
void usock_sendstr(int client_sock, const char* str);

#endif
