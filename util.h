#ifndef UTIL_H
#define UTIL_H

#include <string.h>

// mac strlen is 17 bytes + \0
#define MAC_STRLEN 18

void get_mac(char *dest, const char *iface);
void strnrepl(const char *token, const char *replace, char *str, size_t n);

#endif
