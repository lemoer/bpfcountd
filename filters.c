#include "filters.h"

#include <string.h>
#include <stdlib.h>
#include <sys/epoll.h> // for epoll_ctl(), struct epoll_event
#include <unistd.h>

#include "util.h"


void filters_init(filters_ctx *ctx) {
	ctx->filters = list_new();
}

void filters_finish(filters_ctx *ctx) {

	// free the filters
	list_foreach(ctx->filters, f) {
		struct filter *tmp = list_data(f, struct filter);

		close(tmp->fd);
		pcap_close(tmp->pcap_ctx);
		free(tmp);
	}

	list_free(ctx->filters);
}

static void filters_bpfstr_unwind(filters_ctx *ctx, char *bpf_str)
{
	char token[1024 + strlen("${}")];

	list_foreach(ctx->filters, f) {
		struct filter *tmp = list_data(f, struct filter);

		snprintf(token, sizeof(token), "${%s}", tmp->id);
		strnrepl(token, tmp->bpf_str, bpf_str, 4096);
	}
}

static void filters_bpfstr_unwind_finish(filters_ctx *ctx)
{
	list_foreach(ctx->filters, f)
		free(list_data(f, struct filter)->bpf_str);
}

static void filters_prepare_pcap(struct filter *filter, const char* device, int epoll_fd) {
	struct bpf_program bpf;
	struct epoll_event event;
	char errbuf[PCAP_ERRBUF_SIZE];

	memset(&errbuf, 0, sizeof(errbuf));

	filter->pcap_ctx = pcap_create(device, errbuf);
	// TODO: there could be a warning in errbuf even if handle != NULL
	if (!filter->pcap_ctx) {
		fprintf(stderr, "Couldn't open device %s\n", errbuf);
		exit(1);
	}

	if (pcap_set_snaplen(filter->pcap_ctx, 0)) {
		fprintf(stderr, "Error at setting zero snaplen\n");
		exit(1);
	}

	if (pcap_set_buffer_size(filter->pcap_ctx, BUFSIZ)) {
		fprintf(stderr, "Error at setting pcap buffer size\n");
		exit(1);
	}

	if (pcap_set_timeout(filter->pcap_ctx, 1000)) {
		fprintf(stderr, "Error at setting pcap timeout\n");
		exit(1);
	}

	if (pcap_setnonblock(filter->pcap_ctx, 1, errbuf) == PCAP_ERROR) {
		fprintf(stderr, "Can't set pcap handler nonblocking.\n");
		exit(1);
	}

	if (pcap_activate(filter->pcap_ctx)) {
		fprintf(stderr, "Can't activate pcap handler.\n");
		exit(1);
	}

	if (pcap_compile(filter->pcap_ctx, &bpf, filter->bpf_str, 0, PCAP_NETMASK_UNKNOWN) == -1) {
		fprintf(stderr, "Error at compiling bpf \"%s\": %s\n", filter->bpf_str, pcap_geterr(filter->pcap_ctx));
		exit(1);
	}

	if (pcap_setfilter(filter->pcap_ctx, &bpf)) {
		pcap_freecode(&bpf);
		fprintf(stderr, "Can't set pcap filter\n");
		exit(1);
	}

	pcap_freecode(&bpf);

	filter->fd = pcap_get_selectable_fd(filter->pcap_ctx);
	if (filter->fd == PCAP_ERROR) {
		fprintf(stderr, "Can't get file descriptor from pcap handler.");
		exit(1);
	}

	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN;
	event.data.ptr = filter;

	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, filter->fd, &event)) {
		fprintf(stderr, "Can't add pcap to epoll.\n");
		exit(1);
	}
}



void filters_add(filters_ctx *ctx, const char *id, char *bpf_str, const char* device, int epoll_fd) {
	struct filter *instance = malloc(sizeof(*instance));

	// TODO: document maximum len of id
	strncpy(instance->id, id, 1023);
	instance->id[1023] = '\0';
	instance->bpf_str = bpf_str;

	instance->packets_count = 0;
	instance->bytes_count = 0;

	filters_prepare_pcap(instance, device, epoll_fd);

	list_insert(ctx->filters, instance);
}

void filters_load(filters_ctx *ctx, const char *filterfile_path, const char *mac_addr, const char* device, int epoll_fd) {
	// TODO: test with /dev/random as input

	FILE *fp = fopen(filterfile_path, "r");
	char *line = NULL;
	size_t read = 0;
	int line_no = 0;

	fprintf(stderr, "Device: %s\n", device);

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
		strncpy(bpf, bpf_tmp, 4095);
		strnrepl("$MAC", mac_addr, bpf, 4096);
		filters_bpfstr_unwind(ctx, bpf);

		fprintf(stderr, "id: %s; bpf: \"%s\";\n", id, bpf);
		
		filters_add(ctx, id, bpf, device, epoll_fd);
	}

	filters_bpfstr_unwind_finish(ctx);
	free(line);
	fclose(fp);
}

void filters_process(u_char *ptr, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	struct filter *filter = (struct filter *)ptr;
		
	filter->packets_count += 1;
	filter->bytes_count += pkthdr->len;
}

void filters_break(filters_ctx *filters_ctx) {
	list_foreach(filters_ctx->filters, f) {
		struct filter *filter = list_data(f, struct filter);

		pcap_breakloop(filter->pcap_ctx);
	}
}
