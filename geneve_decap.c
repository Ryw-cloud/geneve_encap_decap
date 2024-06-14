#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <time.h>

#define GENEVE_PORT 6081

typedef struct {
    uint16_t classid;
    uint8_t type;
    uint8_t length;
    uint8_t data[4];  // Limited to target IP address now
} GeneveOptions;

typedef struct {
    uint8_t ver_opt;
    uint8_t flags; // O, C, rsvd
    uint16_t proto_type;
    uint8_t vni[3];
    uint8_t reserved;
    GeneveOptions options;
} GeneveHeader;

void extract_inner_packet(const uint8_t* geneve_packet, uint8_t* inner_packet, uint32_t* inner_packet_len) {
    struct ether_header* eth_header = (struct ether_header*)geneve_packet;
    struct ip* ip_header = (struct ip*)(geneve_packet + sizeof(struct ether_header));
    struct udphdr* udp_header = (struct udphdr*)(geneve_packet + sizeof(struct ether_header) + sizeof(struct ip));
    GeneveHeader* geneve_header = (GeneveHeader*)(geneve_packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));

    uint32_t geneve_header_len = sizeof(GeneveHeader);
    uint32_t offset = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + geneve_header_len;
    uint32_t geneve_packet_len = ntohs(ip_header->ip_len) - sizeof(struct ip) - sizeof(struct udphdr) - geneve_header_len;

    memcpy(inner_packet, geneve_packet + offset, geneve_packet_len);
    *inner_packet_len = geneve_packet_len;
}

void read_and_extract_packet(const char* filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return;
    }

    struct pcap_pkthdr header;
    const uint8_t* packet = pcap_next(handle, &header);
    if (packet == NULL) {
        fprintf(stderr, "Error reading packet from pcap file\n");
        pcap_close(handle);
        return;
    }

    uint8_t inner_packet[1500];
    uint32_t inner_packet_len;
    extract_inner_packet(packet, inner_packet, &inner_packet_len);

    // Save the extracted inner packet to a new pcap file
    pcap_t* pcap = pcap_open_dead(DLT_EN10MB, 1500);
    pcap_dumper_t* dumper = pcap_dump_open(pcap, "extracted_inner_packet.pcap");
    if (dumper == NULL) {
        fprintf(stderr, "Error opening pcap file for writing: %s\n", pcap_geterr(pcap));
        pcap_close(pcap);
        return;
    }

    struct pcap_pkthdr pcap_header;
    pcap_header.ts.tv_sec = time(NULL);
    pcap_header.ts.tv_usec = 0;
    pcap_header.caplen = inner_packet_len;
    pcap_header.len = inner_packet_len;

    pcap_dump((u_char*)dumper, &pcap_header, inner_packet);
    pcap_dump_close(dumper);
    pcap_close(pcap);

    printf("Inner packet extracted and saved to extracted_inner_packet.pcap\n");

    pcap_close(handle);
}

int main() {
    read_and_extract_packet("generated_packet.pcap");
    return 0;
}