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
#define GENEVE_VNI 0x0b
#define OPTION_CLASSID 0xFF01

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

void generate_option(uint8_t* tlv_data, uint8_t target_ip[4], int path_len, GeneveOptions* tlv_option) {
    tlv_option->classid = htons(OPTION_CLASSID);
    tlv_option->type = 0x00;
    tlv_option->length = path_len;
    tlv_option->data[0] = target_ip[0];
    tlv_option->data[1] = target_ip[1];
    tlv_option->data[2] = target_ip[2];
    tlv_option->data[3] = target_ip[3];

    //if (4 * sizeof(target_ip) <= sizeof(tlv_option->data)) {
    //memcpy(tlv_option->data, target_ip, sizeof(target_ip));  // dont know why it does not work here
    //}
    //else {
        // Handle error: target_ip is too large to fit in tlv_option.data
       //fprintf(stderr, "Error: target_ip is too large to fit in tlv_option.data\n");
    //}

}

void generate_packet(uint8_t* packet, const uint8_t* captured_packet, uint32_t captured_len, uint8_t target_ip[4], int path_len) {
    static int it = 63;
    uint8_t tlv_data[4];

    struct ether_header* eth_header = (struct ether_header*)packet;
    struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
    GeneveHeader* geneve_header = (GeneveHeader*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
    struct ether_header* inner_eth_header = (struct ether_header*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + sizeof(GeneveHeader));
    struct ip* inner_ip_header = (struct ip*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + sizeof(GeneveHeader) + sizeof(struct ether_header));
    struct udphdr* inner_udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + sizeof(GeneveHeader) + sizeof(struct ether_header) + sizeof(struct ip));

    // Fill Ethernet header
    memcpy(eth_header->ether_shost, "\x0e\xe1\x2d\x94\x39\x99", 6); // Dont know if it needs to specify here
    memcpy(eth_header->ether_dhost, "\x46\x3c\x24\x1f\xa5\xa9", 6);
    eth_header->ether_type = htons(ETHERTYPE_IP);

    // Fill outer IP header
    ip_header->ip_hl = 5;
    ip_header->ip_v = 4;
    ip_header->ip_tos = 0;
    ip_header->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + sizeof(GeneveHeader) + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr)); 
    ip_header->ip_id = 0;
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 64;
    ip_header->ip_p = IPPROTO_UDP;
    ip_header->ip_src.s_addr = inet_addr("45.33.56.162"); // Real source here
    ip_header->ip_dst.s_addr = inet_addr("45.79.169.39"); //Real dest here
    ip_header->ip_sum = 0;  // Kernel will fill the correct checksum

    // Fill UDP header
    udp_header->source = htons(12345);
    udp_header->dest = htons(GENEVE_PORT);
    udp_header->len = htons(sizeof(struct udphdr) + sizeof(GeneveHeader) + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
    udp_header->check = 0;  // No checksum

    // Fill Geneve header
    geneve_header->ver_opt = 2; // 2*4 bytes of option here
    geneve_header->flags = 0;
    geneve_header->proto_type = htons(0x6558);
    geneve_header->vni[0] = (GENEVE_VNI >> 16) & 0xFF;
    geneve_header->vni[1] = (GENEVE_VNI >> 8) & 0xFF;
    geneve_header->vni[2] = GENEVE_VNI & 0xFF;
    geneve_header->reserved = 0;

    GeneveOptions tlv_option;
    generate_option(tlv_data, target_ip, path_len, &tlv_option);
    geneve_header->options = tlv_option;

    // Copy the captured packet as the inner packet
    memcpy(inner_eth_header, captured_packet, captured_len);
}

void create_test_packet(uint8_t* packet, uint32_t* packet_len) {
    struct ether_header* eth_header = (struct ether_header*)packet;
    struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
    char* payload = (char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));

    // Fill Ethernet header
    memcpy(eth_header->ether_shost, "\x0e\xe1\x2d\x94\x39\x99", 6);
    memcpy(eth_header->ether_dhost, "\x46\x3c\x24\x1f\xa5\xa9", 6);
    eth_header->ether_type = htons(ETHERTYPE_IP);

    // Fill IP header
    ip_header->ip_hl = 5;
    ip_header->ip_v = 4;
    ip_header->ip_tos = 0;
    ip_header->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + 8);  // Payload length is 8
    ip_header->ip_id = 0;
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 64;
    ip_header->ip_p = IPPROTO_UDP;
    ip_header->ip_sum = 0;  // Kernel will fill the correct checksum
    ip_header->ip_src.s_addr = inet_addr("192.168.0.1");
    ip_header->ip_dst.s_addr = inet_addr("192.168.0.2");

    // Fill UDP header
    udp_header->source = htons(12345);
    udp_header->dest = htons(54321);
    udp_header->len = htons(sizeof(struct udphdr) + 8);  // Payload length is 8
    udp_header->check = 0;  // No checksum

    // Fill payload
    strcpy(payload, "TEST1234");

    // Set the packet length
    *packet_len = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + 8;
}

int main() {
    uint8_t target_ip[4] = { 7, 7, 7, 7 };
    uint8_t test_packet[1500];
    uint32_t test_packet_len;

    create_test_packet(test_packet, &test_packet_len);

    uint8_t packet[1500];  // Allocate memory for packet

    generate_packet(packet, test_packet, test_packet_len, target_ip, 1);


    // Save the generated packet to a pcap file
    pcap_t* pcap;
    pcap_dumper_t* dumper;
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap = pcap_open_dead(DLT_EN10MB, 1500);
    dumper = pcap_dump_open(pcap, "generated_packet.pcap");
    if (dumper == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", pcap_geterr(pcap));
        return 0;
    }

    struct pcap_pkthdr pcap_header;
    pcap_header.ts.tv_sec = time(NULL);
    pcap_header.ts.tv_usec = 0;
    pcap_header.caplen = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + sizeof(GeneveHeader) + test_packet_len;
    pcap_header.len = pcap_header.caplen;

    pcap_dump((u_char*)dumper, &pcap_header, packet);
    pcap_dump_close(dumper);
    pcap_close(pcap);

    return 0;
}
/* 
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 2;
    }

    if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
        fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle));
        return 2;
    }

    pcap_close(handle);

    printf("Packet sent.\n");
    return 0;
}

*/
