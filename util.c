#include "util.h"

#include <stdlib.h>
#include <stdio.h>

void get_mac(char *dest, const char *iface) {
	// TODO: how long must be size
	const int path_len = 140;
	char addr_path[path_len];

	snprintf(addr_path, path_len, "/sys/class/net/%s/address", iface);

	FILE *fp;
	fp = fopen(addr_path, "r");

	if (fp == NULL) {
		fprintf(stderr, "Interface in %s not found\n", addr_path);
		exit(1);
	}

	fgets(dest, MAC_STRLEN, fp);
	fclose(fp);
}

void strnrepl(const char *token, const char *replace, char *str, size_t n) {
	char *ptr = str;
	char *p_behind;
	size_t length_new = strlen(str);

	while (1) {
		// find next occurance of token
		ptr = strstr(ptr, token);

		if (ptr == NULL)
			// no occurence found.
			return;

		// calculate the new length and check for overflow
		length_new += strlen(replace) - strlen(token);
		if (length_new >= n)
			return;

		// this points to the position behind the token
		p_behind = ptr + strlen(token);

		memmove(ptr + strlen(replace), p_behind, strlen(p_behind));
		memcpy(ptr, replace, strlen(replace));
		str[length_new] = 0x00;
	}
}

