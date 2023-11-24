#include <stdio.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#define saveBufSize 8192

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char savebuf[saveBufSize];
    int packetNum;

    // 사용자로부터 캡처할 패킷의 수를 입력받기.
    printf("number of captured packets: ");
    scanf("%d", &packetNum);

    // 저장할 파일을 생성 및 열기.
    FILE *writeFile = fopen("test.txt", "w");
    if (writeFile == NULL) {
        fprintf(stderr, "파일을 열 수 없습니다.\n");
        return 1;
    }
    fprintf(writeFile, "Start capture\n");

    // 캡처할 네트워크 선택 및 패킷 캡처 준비.
    handle = pcap_open_live("en0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "패킷 캡처를 시작할 수 없습니다: %s\n", errbuf);
        fclose(writeFile);
        return 2;
    }

    // 패킷 캡처 루프.
    pcap_loop(handle, packetNum, packet_handler, (u_char *)writeFile);

    // 파일 및 캡처 종료.
    fclose(writeFile);
    pcap_close(handle);

    return 0;
}

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    FILE *writeFile = (FILE *)user;
    struct ether_header *eth_header = (struct ether_header *)packet;
    struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);
    u_int16_t ether_type = ntohs(eth_header->ether_type);

    // Ethernet 헤더 정보를 파일에 기록
    fprintf(writeFile, "Ethernet Header\n");
    fprintf(writeFile, "  - Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
            eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2],
            eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5]);
    fprintf(writeFile, "  - Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
            eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2],
            eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
    fprintf(writeFile, "  - Ether Type: 0x%04x\n", ether_type);

    // IP 헤더 정보를 파일에 기록
    if (ether_type == ETHERTYPE_IP) {
        fprintf(writeFile, "IP Header\n");
        fprintf(writeFile, "  - Source IP: %s\n", inet_ntoa(ip_header->ip_src));
        fprintf(writeFile, "  - Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
        fprintf(writeFile, "  - Protocol: %d\n", ip_header->ip_p);

        // TCP, UDP, ICMP 헤더 정보를 파일에 기록
        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + ETHER_HDR_LEN + ip_header->ip_hl * 4);
            fprintf(writeFile, "TCP Header\n");
            fprintf(writeFile, "  - Source Port: %d\n", ntohs(tcp_header->th_sport));
            fprintf(writeFile, "  - Destination Port: %d\n", ntohs(tcp_header->th_dport));
            fprintf(writeFile, "  - Sequence Number: %u\n", ntohl(tcp_header->th_seq));
            fprintf(writeFile, "  - Acknowledgment Number: %u\n", ntohl(tcp_header->th_ack));
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr *)(packet + ETHER_HDR_LEN + ip_header->ip_hl * 4);
            fprintf(writeFile, "UDP Header\n");
            fprintf(writeFile, "  - Source Port: %d\n", ntohs(udp_header->uh_sport));
            fprintf(writeFile, "  - Destination Port: %d\n", ntohs(udp_header->uh_dport));
        } else if (ip_header->ip_p == IPPROTO_ICMP) {
            struct icmphdr *icmp_header = (struct icmphdr *)(packet + ETHER_HDR_LEN + ip_header->ip_hl * 4);
            fprintf(writeFile, "ICMP Header\n");
//            printf("  - Type: %d\n", icmp_header->type);
//            printf("  - Code: %d\n", icmp_header->code);
        }
    }
    fprintf(writeFile, "\n--------------------------------------------\n");
}
