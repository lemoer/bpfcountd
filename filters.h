#ifndef FILTERS_H
#define FILTERS_H

#include <pcap.h>

#include "list.h"

struct filter {
	char id[1024];
	struct bpf_program *bpf;
	unsigned long long packets_count;
	unsigned long long bytes_count;
};

typedef struct {
	pcap_t *pcap_ctx;
	struct list *filters;
} filters_ctx;

void filters_init(filters_ctx *ctx, pcap_t* pcap_ctx);
void filters_finish(filters_ctx *ctx);
void filters_add(filters_ctx *ctx, const char *id, const char* bpf_str);
void filters_load(filters_ctx *ctx, const char *filterfile_path, const char* mac_addr);

void filters_process(filters_ctx *ctx, const struct pcap_pkthdr *pkthdr, const u_char *packet);

#endif
