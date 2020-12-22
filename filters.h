#ifndef FILTERS_H
#define FILTERS_H

#include <pcap.h>

#include "list.h"

struct filter {
	char id[1024];
	char *bpf_str;
	unsigned long long packets_count;
	unsigned long long bytes_count;
	pcap_t *pcap_ctx;
	int fd;
};

typedef struct {
	pcap_t *pcap_ctx;
	struct list *filters;
	int count;
} filters_ctx;

void filters_init(filters_ctx *ctx);
void filters_finish(filters_ctx *ctx);
void filters_add(filters_ctx *ctx, const char *id, char *bpf_str, const char* device, int epoll_fd);
void filters_load(filters_ctx *ctx, const char *filterfile_path, const char* mac_addr, const char* device, int epoll_fd);

void filters_process(u_char *ptr, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void filters_break(filters_ctx *filters_ctx);

#endif
