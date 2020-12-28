#include <pcap.h>
#include <ctype.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/epoll.h> // for epoll_create1(), epoll_ctl(), struct epoll_event

#include "util.h"
#include "filters.h"
#include "usock.h"
#include "list.h"

#define MAX_EVENTS 32

static struct epoll_event events[MAX_EVENTS];

struct config {
	const char *device;       // TODO: rename
	const char *filters_path; // TODO: rename
	const char *usock_path;
	const char *prefilter_str;
	char mac_addr[MAC_STRLEN];
};

typedef struct {
	struct config config;
	filters_ctx filters_ctx;

	pcap_t *pcap_ctx;
	int fd;
} bpfcountd_ctx;


static void prepare_pcap(bpfcountd_ctx *ctx, const char* device, int epoll_fd) {
	struct bpf_program bpf;
	struct epoll_event event;
	char errbuf[PCAP_ERRBUF_SIZE];

	memset(&errbuf, 0, sizeof(errbuf));

	ctx->pcap_ctx = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
	// TODO: there could be a warning in errbuf even if handle != NULL
	if (!ctx->pcap_ctx) {
		fprintf(stderr, "Couldn't open device %s\n", errbuf);
		exit(1);
	}

	if (pcap_setnonblock(ctx->pcap_ctx, 1, errbuf) == PCAP_ERROR) {
		fprintf(stderr, "Can't set pcap handler nonblocking.\n");
		exit(1);
	}

	if (ctx->config.prefilter_str) {
		if (pcap_compile(ctx->pcap_ctx, &bpf, ctx->config.prefilter_str,
				 0, PCAP_NETMASK_UNKNOWN) == -1) {
			fprintf(stderr, "Error at compiling bpf \"%s\": %s\n",
				ctx->config.prefilter_str,
				pcap_geterr(ctx->pcap_ctx));
			exit(1);
		}

		if (pcap_setfilter(ctx->pcap_ctx, &bpf)) {
			pcap_freecode(&bpf);
			fprintf(stderr, "Can't set pcap filter \"%s\": %s\n",
				ctx->config.prefilter_str,
				pcap_geterr(ctx->pcap_ctx));
			exit(1);
		}

		pcap_freecode(&bpf);
	}

	ctx->fd = pcap_get_selectable_fd(ctx->pcap_ctx);
	if (ctx->fd == PCAP_ERROR) {
		fprintf(stderr, "Can't get file descriptor from pcap handler.");
		exit(1);
	}

	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN;
	event.data.ptr = ctx->pcap_ctx;

	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ctx->fd, &event)) {
		fprintf(stderr, "Can't add pcap to epoll.\n");
		exit(1);
	}

	fprintf(stderr, "Device: %s\n", device);
}

static void help(const char* path) {
	fprintf(stderr, "%s -i <interface> [-F <prefilter-expr>] -f <filterfile> [-u <unixpath>] [-h]\n\n", path);

	fprintf(stderr, "-F <prefilter-expr>   an optional prefilter BPF expression, installed in the kernel\n");
	fprintf(stderr, "-f <filterfile>       a the main file where each line contains an id and a bpf\n");
	fprintf(stderr, "                      filter, seperated by a semicolon\n");
	fprintf(stderr, "-u <unixpath>         path to the unix info socket (default is ./test.sock)\n");
}

static void prepare_config(struct config *cfg, int argc, char *argv[]) {
	int c;

	// default settings
	// TODO: device should be iface?
	cfg->device = NULL;
	cfg->filters_path = NULL;
	cfg->usock_path = "test.sock";
	cfg->prefilter_str = NULL;

	opterr = 0;
	while ((c = getopt(argc, argv, "hi:F:f:u:")) != -1) {
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
		case 'F':
			cfg->prefilter_str = optarg;
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


static void callback(u_char *ptr, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	bpfcountd_ctx *ctx = (bpfcountd_ctx *) ptr;
	filters_process(&ctx->filters_ctx, pkthdr, packet);
}

static int term = 0;

static void sigint_handler(int signo) {
	term = 1;
}

static void
bpfcountd_init(bpfcountd_ctx *ctx, int argc, char *argv[], int epoll_fd) {
	prepare_config(&ctx->config, argc, argv);

	// get a pcap handle
	prepare_pcap(ctx, ctx->config.device, epoll_fd);

	// initialize the filter unit
	filters_init(&ctx->filters_ctx, ctx->pcap_ctx);
	filters_load(
		&ctx->filters_ctx,
		ctx->config.filters_path,
		ctx->config.mac_addr
	);
}

static void bpfcountd_finish(bpfcountd_ctx *ctx) {
	close(ctx->fd);
	pcap_close(ctx->pcap_ctx);
	filters_finish(&ctx->filters_ctx);
}

int main(int argc, char *argv[]) {
	int epoll_fd = epoll_create1(0);

	if (epoll_fd < 0) {
		fprintf(stderr, "Can't create epoll file descriptor.\n");
		exit(1);
	}

	bpfcountd_ctx ctx = {};

	bpfcountd_init(&ctx, argc, argv, epoll_fd);

	int usock = usock_prepare(ctx.config.usock_path, epoll_fd);
	int usock_client;
	int result = 0;

	if (signal(SIGINT, sigint_handler) == SIG_ERR)
		fprintf(stderr, "Can't establish SIGINT handler.");


	// TODO: find out if the method drops packets
	while(!term) {
		int ev_count = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);

		for(int i = 0; i < ev_count; i++) {
			pcap_t *pcap_ctx = events[i].data.ptr;

			if (pcap_ctx) {
				int res = pcap_dispatch(pcap_ctx, 100, callback, (u_char *) &ctx);
				if (res == -1) {
					printf("ERROR: %s\n", pcap_geterr(pcap_ctx));
					result = 1;
					break;
				}
			// pcap_ctx == NULL indicates unix socket event
			} else if ((usock_client = usock_accept(usock)) != -1) {
				list_foreach(ctx.filters_ctx.filters, f) {
					struct filter *tmp = list_data(f, struct filter);
					char buf[1067];
					memset(buf, 0x00, sizeof(buf));

					snprintf(buf, 1067, "%s:%llu:%llu\n", tmp->id, tmp->bytes_count, tmp->packets_count);
					usock_sendstr(usock_client, buf);
				}

				usock_finish(usock_client);
			}
		}

	}

	usock_finish(usock);
	unlink(ctx.config.usock_path);
	bpfcountd_finish(&ctx);
	close(epoll_fd);

	return result;
}
