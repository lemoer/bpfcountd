#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <netinet/ether.h>

#include "list.h"

#define SIZE_ETHERNET 14

pcap_t *open_pcap(int argc, char* argv[]) {
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	bzero(&errbuf, sizeof(errbuf));

	if (argc > 1) {
		dev = argv[1];
	} else {
		fprintf(stderr, "You have to supply an interface as first parameter!\n");
		exit(1);
	}

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s\n", errbuf);
		return NULL;
	}
	
	fprintf(stderr, "Device: %s\n", dev);
	return handle;
}


// TODO: pack this in "useless"
pcap_t* g_handle = NULL;

struct filter {
	const char *descr;
	struct bpf_program *bpf;
};

struct list* filters;

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	
	list_foreach(filters, f) {
		struct filter *tmp = list_data(f, struct filter);
		
		if (pcap_offline_filter(tmp->bpf, pkthdr, packet)) {
			printf("length[%d] ", pkthdr->len);
			printf("%s\n", tmp->descr);
		}
	}
	
	// TODO: remove
	fflush(stdout);
}

void add_filter(struct list* filters, const char* descr, const char* bpf) {
	struct filter* tmp = (struct filter*) malloc(sizeof(struct filter));

	tmp->descr = descr;
	tmp->bpf = (struct bpf_program*) malloc(sizeof(struct bpf_program));
	pcap_compile(g_handle, tmp->bpf, bpf, 0, 0); //TODO return value && PCAP_NET_UNKNOWN foobar
	
	list_insert(filters, tmp);
}

int main(int argc, char *argv[]) {
	pcap_t *handle = open_pcap(argc, argv);
	g_handle = handle;
	
	if (handle == NULL)
		return 2;


  filters = list_new();

	add_filter(filters, "arp-req", "arp[6:2] == 1");
	add_filter(filters, "arp-rep-norm", "not ether broadcast and arp[6:2] == 2");
	add_filter(filters, "arp-rep-grat", "ether broadcast and arp[6:2] == 2");

	// TODO: find out if the method drops packets
	while(1) {
		pcap_dispatch(handle, 100, callback, NULL);
		printf("##############################################\n");
	}
	list_free(filters);
	pcap_close(handle);
	return 0;
}
