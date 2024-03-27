#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <netinet/in.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void autoprint(uint8_t* buf, unsigned int size, char* sep){
	for(int i = 0; i < size; i++){ 
		if(size == 4) printf("%02d", buf[i]); 
		else printf("%02x", buf[i]); 
		if(i == (size - 1)) break;
		printf("%s", sep);
	}
	printf("\n");
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);

		struct libnet_ethernet_hdr* ethernet_hdr = (struct libnet_ethernet_hdr*)packet;
		packet += sizeof(struct libnet_ethernet_hdr);

		struct libnet_ipv4_hdr* ipv4_hdr = (struct libnet_ipv4_hdr*)packet;
		packet += sizeof(struct libnet_ipv4_hdr);

		struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)packet;
		packet += sizeof(struct libnet_tcp_hdr);

		uint8_t* data = (uint8_t*)packet;
		unsigned int datalen = header->caplen - (sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr));
        unsigned int maxlen=datalen;
        if(datalen > 20) maxlen = 20;
		uint16_t eth_type = ntohs(ethernet_hdr->ether_type);
		uint8_t protocol = ipv4_hdr->ip_p;

		if(eth_type == ETHERTYPE_IP){
			if(protocol == IPPROTO_TCP){
                		printf("Ethernet Header\n");
				uint8_t* src_addr = ethernet_hdr->ether_shost;
				printf("src mac : ");
				autoprint(src_addr, ETHER_ADDR_LEN, ":");
                		uint8_t* dst_addr = ethernet_hdr->ether_dhost;
				printf("dst mac : ");
				autoprint(dst_addr, ETHER_ADDR_LEN, ":");

                		printf("IP Header\n");
				uint8_t* src_ip = (uint8_t*)&ipv4_hdr->ip_src;
				printf("src ip : ");
				autoprint(src_ip, sizeof(struct in_addr), ".");
                		uint8_t* dst_ip = (uint8_t*)&ipv4_hdr->ip_dst;
				printf("dst ip : ");
				autoprint(dst_ip, sizeof(struct in_addr), ".");

				printf("TCP Header\n");
				uint16_t src_port = ntohs(tcp_hdr->th_sport);
				printf("src port : %d\n", src_port);
                		uint16_t dst_port = ntohs(tcp_hdr->th_dport);
				printf("dst port : %d\n", dst_port);
                
				printf("Payload(Data)\n");
				autoprint(data, maxlen, " ");
				printf("\n");
			}
		}
	}

	pcap_close(pcap);
}
