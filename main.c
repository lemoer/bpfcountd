#include <pcap.h>
#include <ctype.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "util.h"
#include "filters.h"
#include "usock.h"
#include "list.h"


struct config {
	const char *device;
	const char *filters_path;
	const char *usock_path;
	char mac_addr[MAC_STRLEN];
};

typedef struct {
	struct config config;
	filters_ctx filters_ctx;

	pcap_t *pcap_ctx;
} bpfcountd_ctx;


void prepare_pcap(bpfcountd_ctx *ctx, const char* device) {
	char errbuf[PCAP_ERRBUF_SIZE];

	memset(&errbuf, 0, sizeof(errbuf));

	ctx->pcap_ctx = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
	// TODO: there could be a warning in errbuf even if handle != NULL
	if (!ctx->pcap_ctx) {
		fprintf(stderr, "Couldn't open device %s\n", errbuf);
		exit(1);
	}

	printf(stderr, "Device: %s\n", device);
}

void help(const char* path) {
	fprintf(stderr, "%s -i <interface> -f <filterfile> [-u <unixpath>] [-h]\n\n", path);

	fprintf(stderr, "-f <filterfile>       a the main file where each line contains an id and a bpf\n");
	fprintf(stderr, "                      filter, seperated by a semicolon\n");
	fprintf(stderr, "-u <unixpath>         path to the unix info socket (default is ./test.sock)\n");
}

void prepare_config(struct config *cfg, int argc, char *argv[]){
	int c;

	// default settings
	cfg->device = NULL;
	cfg->filters_path = NULL;
	cfg->usock_path = "test.sock";

	opterr = 0;
	while ((c = getopt(argc, argv, "hi:f:u:")) != -1) {
		switch (c) {
		case 'i':
			cfg->device = optarg;
			break;
		case 'h':
			help(argv[0]);
			exit(0);
		case 'u':
			cfg->usock_path = optarg;
			break;
		case 'f':
			cfg->filters_path = optarg;
			break;
		case '?':
			if (optopt == 'i')
				fprintf(stderr, "Option -%c requires an argument.\n", optopt);
			else if (isprint (optopt))
				fprintf(stderr, "Unknown option -%c.\n", optopt);
			else
				fprintf(stderr, "Unknown option character \\x%x.\n", optopt);
			exit(1);
		default:
			abort();
		}
	}

	if (!cfg->device) {
		fprintf(stderr, "No interface was was set.\n");
		exit(1);
	}

	get_mac(cfg->mac_addr, cfg->device);

	if (!cfg->filters_path) {
		fprintf(stderr, "You have to supply a filterfile -f <file>.\n");
		exit(1);
	}

}


void callback(u_char *ptr, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	bpfcountd_ctx *ctx = (bpfcountd_ctx *) ptr;
	filters_process(&ctx->filters_ctx, pkthdr, packet);
}

int term = 0;

void sigint_handler(int signo) {
	term = 1;
}

void bpfcountd_init(bpfcountd_ctx *ctx, int argc, char *argv[]) {
	prepare_config(&ctx->config, argc, argv);

	// get a pcap handle
	prepare_pcap(ctx, ctx->config.device);

	// initialize the filter unit
	filters_init(&ctx->filters_ctx, ctx->pcap_ctx);
	filters_load(
		&ctx->filters_ctx,
		ctx->config.filters_path,
		ctx->config.mac_addr
	);
}

void bpfcountd_finish(bpfcountd_ctx *ctx) {
	pcap_close(ctx->pcap_ctx);
	filters_finish(&ctx->filters_ctx);
}

int main(int argc, char *argv[]) {
	bpfcountd_ctx ctx = {};

	bpfcountd_init(&ctx, argc, argv);

	int usock = usock_prepare(ctx.config.usock_path);
	int usock_client;

	if (signal(SIGINT, sigint_handler) == SIG_ERR)
		fprintf(stderr, "Can't establish SIGINT handler.");


	// TODO: find out if the method drops packets
	while(term == 0) {
		pcap_dispatch(ctx.pcap_ctx, 100, callback, (u_char *) &ctx);
		if((usock_client = usock_accept(usock)) != -1) {

			list_foreach(ctx.filters_ctx.filters, f) {
				struct filter *tmp = list_data(f, struct filter);
				char buf[1024];
				memset(buf, 0x00, sizeof(buf));

				snprintf(buf, 1024, "%s:%llu:%llu\n", tmp->id, tmp->bytes_count, tmp->packets_count);
				usock_sendstr(usock_client, buf);
			}

			usock_finish(usock_client);
		}
	}

	usock_finish(usock);
	bpfcountd_finish(&ctx);
	return 0;
}
