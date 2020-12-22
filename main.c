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

struct epoll_event events[MAX_EVENTS];

struct config {
	const char *device;       // TODO: rename
	const char *filters_path; // TODO: rename
	const char *usock_path;
	char mac_addr[MAC_STRLEN];
};

typedef struct {
	struct config config;
	filters_ctx filters_ctx;
} bpfcountd_ctx;

bpfcountd_ctx ctx;

void help(const char* path) {
	fprintf(stderr, "%s -i <interface> -f <filterfile> [-u <unixpath>] [-h]\n\n", path);

	fprintf(stderr, "-f <filterfile>       a the main file where each line contains an id and a bpf\n");
	fprintf(stderr, "                      filter, seperated by a semicolon\n");
	fprintf(stderr, "-u <unixpath>         path to the unix info socket (default is ./test.sock)\n");
}

void prepare_config(struct config *cfg, int argc, char *argv[]){
	int c;

	// default settings
	// TODO: device should be iface?
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


int term = 0;

void sigint_handler(int signo) {
	term = 1;
	filters_break(&ctx.filters_ctx);
}

void bpfcountd_init(bpfcountd_ctx *ctx, int argc, char *argv[], int epoll_fd) {
	prepare_config(&ctx->config, argc, argv);

	// initialize the filter unit
	filters_init(&ctx->filters_ctx);
	filters_load(
		&ctx->filters_ctx,
		ctx->config.filters_path,
		ctx->config.mac_addr,
		ctx->config.device,
		epoll_fd
	);
}

int main(int argc, char *argv[]) {
	int epoll_fd = epoll_create1(0);

	if (epoll_fd < 0) {
		fprintf(stderr, "Can't create epoll file descriptor.\n");
		exit(1);
	}

	bpfcountd_init(&ctx, argc, argv, epoll_fd);

	int usock = usock_prepare(ctx.config.usock_path, epoll_fd);
	int usock_client;
	int result = 0;

	if (signal(SIGINT, sigint_handler) == SIG_ERR)
		fprintf(stderr, "Can't establish SIGINT handler.");


	// TODO: find out if the method drops packets
	while(!term) {
		int ev_count = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);

		if (term)
			break;

		for(int i = 0; i < ev_count; i++) {
			struct filter *filter = events[i].data.ptr;

			if (filter) {
				int res = pcap_dispatch(filter->pcap_ctx, 100, filters_process, (u_char *) filter);
				switch (res) {
				case PCAP_ERROR:
					printf("ERROR: %s\n", pcap_geterr(filter->pcap_ctx));
					result = 1;
					/* fall through */
				case PCAP_ERROR_BREAK:
					break;
				}
			// filter == NULL indicates unix socket event
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

	fprintf(stderr, "Shutting down...\n");
	usock_finish(usock);
	unlink(ctx.config.usock_path);
	filters_finish(&ctx.filters_ctx);
	close(epoll_fd);
	fprintf(stderr, "Shutdown finished, bye\n");

	return result;
}
