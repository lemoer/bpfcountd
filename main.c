#include <pcap.h>
#include <ctype.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "usock.h"
#include "list.h"

struct config {
	const char *device;
	const char *filters_path;
	const char *usock_path;
};

struct config *config;

void help(const char* path) {
	fprintf(stderr, "%s -i <interface> -f <filterfile> [-u <unixpath>] [-h]\n\n", path);

	fprintf(stderr, "-f <filterfile>       a the main file where each line contains an id and a bpf\n");
	fprintf(stderr, "                      filter, seperated by a semicolon\n");
	fprintf(stderr, "-u <unixpath>         path to the unix info socket (default is ./test.sock)\n");
}

void config_prepare(int argc, char *argv[]){
	int c;

	config = malloc(sizeof(struct config));
	config->device = NULL;
	config->filters_path = NULL;
	config->usock_path = "test.sock";

	opterr = 0;
	while ((c = getopt(argc, argv, "hi:f:u:")) != -1) {
		switch (c) {
		case 'i':
			config->device = optarg;
			break;
		case 'h':
			help(argv[0]);
			exit(0);
		case 'u':
			config->usock_path = optarg;
			break;
		case 'f':
			config->filters_path = optarg;
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
}


void config_finish() {
	free(config);
}

pcap_t *open_pcap() {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	bzero(&errbuf, sizeof(errbuf));

	if (config->device == NULL) {
		fprintf(stderr, "You have to supply an interface -i <interface>.\n");
		exit(1);
	}

	handle = pcap_open_live(config->device, BUFSIZ, 1, 1000, errbuf);
	// TODO: there could be a warning in errbuf even if handle != NULL
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s\n", errbuf);
		exit(1);
	}
	
	fprintf(stderr, "Device: %s\n", config->device);
	return handle;
}


// TODO: pack this in "useless"
pcap_t* g_handle = NULL;

struct filter {
	char *id;
	struct bpf_program *bpf;
	unsigned long long packets_count;
	unsigned long long bytes_count;
};

struct list* filters;

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	list_foreach(filters, f) {
		struct filter *tmp = list_data(f, struct filter);
		
		if (pcap_offline_filter(tmp->bpf, pkthdr, packet)) {
			tmp->packets_count += 1;
			tmp->bytes_count += pkthdr->len;
		}
	}
}

void add_filter(struct list* filters, char* id, const char* bpf) {
	struct filter* tmp = (struct filter*) malloc(sizeof(struct filter));

	tmp->id = id;
	tmp->bpf = (struct bpf_program*) malloc(sizeof(struct bpf_program));
	tmp->packets_count = 0;
	tmp->bytes_count = 0;

	if (pcap_compile(g_handle, tmp->bpf, bpf, 0, PCAP_NETMASK_UNKNOWN) == -1) {
		fprintf(stderr, "Error at compiling bpf \"%s\": %s\n", bpf, pcap_geterr(g_handle));
		exit(1);
	}

	list_insert(filters, tmp);
}

void read_filters() {
	if (config->filters_path == NULL) {
		fprintf(stderr, "You have to supply a filterfile -f <file>.\n");
		exit(1);
	}

	FILE *fp = fopen(config->filters_path, "r");
	char *line = NULL;
	size_t read = 0;
	int line_no = 0;

	if (fp == NULL) {
		perror("Error while opening the file");
		exit(1);
	}

	while ((read = getline(&line, &read, fp)) != -1) {
		line_no++;
		line[read-1] = 0; // remove the \n at the end of the line

		// skip the line if it's empty
		if (read == 1)
			continue;

		char *id = strtok(line, ";");
		char *bpf = strtok(NULL, ";");

		if (id == NULL || bpf == NULL) {
			fprintf(stderr, "Wrong format in filterfile in line %d.\n", line_no);
			exit(1);
		}

		// create new buffers for id and bpf, since they will get
		// free when line will be free
		id = strdup(id);
		bpf = strdup(bpf);

		fprintf(stderr, "id: %s; bpf: \"%s\";\n", id, bpf);

		add_filter(filters, id, bpf);

		// the bpf is not needed anymore
		free(bpf);
	}

	free(line);
	fclose(fp);
}

int term = 0;

void sigint_handler(int signo) {
	term = 1;
}

int main(int argc, char *argv[]) {
	config_prepare(argc, argv);

	pcap_t *handle = open_pcap();
	g_handle = handle;

	filters = list_new();
	read_filters();

	int usock = usock_prepare(config->usock_path);
	int usock_client;

	if (signal(SIGINT, sigint_handler) == SIG_ERR)
		fprintf(stderr, "Can't establish SIGINT handler.");


	// TODO: find out if the method drops packets
	while(term == 0) {
		pcap_dispatch(handle, 100, callback, NULL);
		if((usock_client = usock_accept(usock)) != -1) {

			list_foreach(filters, f) {
				struct filter *tmp = list_data(f, struct filter);
				char buf[1024];
				memset(buf, 0x00, sizeof(buf));

				snprintf(buf, 1024, "%s:%llu:%llu\n", tmp->id, tmp->bytes_count, tmp->packets_count);
				usock_sendstr(usock_client, buf);
			}

			usock_finish(usock_client);
		}
	}

	// free the filters
	list_foreach(filters, f) {
		struct filter *tmp = list_data(f, struct filter);

		free(tmp->id);
		free(tmp->bpf);
		free(tmp);
	}

	list_free(filters);
	pcap_close(handle);
	usock_finish(usock);
	config_finish();
	return 0;
}
