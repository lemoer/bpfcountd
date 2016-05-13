#include "filters.h"

#include <string.h>
#include <stdlib.h>

#include "util.h"


void filters_init(filters_ctx *ctx, pcap_t* pcap_ctx) {
	ctx->filters = list_new();
	ctx->pcap_ctx = pcap_ctx;
}

void filters_finish(filters_ctx *ctx) {

	// free the filters
	list_foreach(ctx->filters, f) {
		struct filter *tmp = list_data(f, struct filter);

		pcap_freecode(tmp->bpf);
		free(tmp->bpf);
		free(tmp);
	}

	list_free(ctx->filters);
}

void filters_add(filters_ctx *ctx, const char *id, const char* bpf_str) {
	struct filter *instance = malloc(sizeof(*instance));

	// TODO: document maximum len of id
	strncpy(instance->id, id, 1023);
	instance->id[1023] = '\0';
	instance->bpf = malloc(sizeof(struct bpf_program));

	instance->packets_count = 0;
	instance->bytes_count = 0;

	if (pcap_compile(ctx->pcap_ctx, instance->bpf, bpf_str, 0, PCAP_NETMASK_UNKNOWN) == -1) {
		fprintf(stderr, "Error at compiling bpf \"%s\": %s\n", bpf_str, pcap_geterr(ctx->pcap_ctx));
		exit(1);
	}

	list_insert(ctx->filters, instance);
}

void filters_load(filters_ctx *ctx, const char *filterfile_path, const char *mac_addr) {
	// TODO: test with /dev/random as input

	FILE *fp = fopen(filterfile_path, "r");
	char *line = NULL;
	size_t read = 0;
	int line_no = 0;

	if (fp == NULL) {
		fprintf(stderr, "Error while opening the filterfile '%s': ", filterfile_path);
		perror("");
		exit(1);
	}

	while ((read = getline(&line, &read, fp)) != -1) {
		line_no++;
		line[read-1] = 0; // remove the \n at the end of the line

		// skip the line if it's empty
		if (read == 1)
			continue;

		char *id = strtok(line, ";");
		char *bpf_tmp = strtok(NULL, ";");

		if (id == NULL || bpf_tmp == NULL) {
			fprintf(stderr, "Wrong format in filterfile in line %d.\n", line_no);
			exit(1);
		}

		// create new buffers for id and bpf, since they will get
		// free when line will be free
		//
		// TODO: here is dump!!
		char *bpf = malloc(4096);
		strncpy(bpf, bpf_tmp, 4096);
		strnrepl("$MAC", mac_addr, bpf, 4096);

		fprintf(stderr, "id: %s; bpf: \"%s\";\n", id, bpf);
		
		filters_add(ctx, id, bpf);

		// the bpf is not needed anymore
		free(bpf);
	}

	free(line);
	fclose(fp);
}

void filters_process(filters_ctx *ctx, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	list_foreach(ctx->filters, f) {
		struct filter *tmp = list_data(f, struct filter);
		
		if (pcap_offline_filter(tmp->bpf, pkthdr, packet)) {
			tmp->packets_count += 1;
			tmp->bytes_count += pkthdr->len;
		}
	}
}
