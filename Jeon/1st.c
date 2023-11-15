#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>

#define MAX_PACKET_SIZE 65536

// ICMP 헤더 구조체
struct icmpheader {
    unsigned char type;
    unsigned char code;
    unsigned short checksum;
    // ICMP 헤더에 대한 다른 필드 추가 가능
};

void print_icmp_header(struct icmpheader *icmpHeader) {
    printf("ICMP Header:\n");
    printf("Type: %u\n", icmpHeader->type);
    printf("Code: %u\n", icmpHeader->code);
    printf("Checksum: 0x%04x\n", ntohs(icmpHeader->checksum));
    // 여기에 필요한 다른 ICMP 헤더 정보 출력 추가 가능
}

// DNS 헤더 구조체
struct dnshdr {
    unsigned short id;
    unsigned char rd : 1;
    unsigned char tc : 1;
    unsigned char aa : 1;
    unsigned char opcode : 4;
    unsigned char qr : 1;
    unsigned char rcode : 4;
    unsigned char cd : 1;
    unsigned char ad : 1;
    unsigned char z : 1;
    unsigned char ra : 1;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
};

void print_dns_header(struct dnshdr *dnsHeader) {
    printf("DNS Header:\n");
    printf("ID: %u\n", ntohs(dnsHeader->id));
    printf("QR: %u\n", dnsHeader->qr);
    printf("Opcode: %u\n", dnsHeader->opcode);
    printf("AA: %u\n", dnsHeader->aa);
    printf("TC: %u\n", dnsHeader->tc);
    printf("RD: %u\n", dnsHeader->rd);
    printf("RA: %u\n", dnsHeader->ra);
    printf("Z: %u\n", dnsHeader->z);
    printf("AD: %u\n", dnsHeader->ad);
    printf("CD: %u\n", dnsHeader->cd);
    printf("RCode: %u\n", dnsHeader->rcode);
    printf("QDCount: %u\n", ntohs(dnsHeader->qdcount));
    printf("ANCount: %u\n", ntohs(dnsHeader->ancount));
    printf("NSCount: %u\n", ntohs(dnsHeader->nscount));
    printf("ARCount: %u\n", ntohs(dnsHeader->arcount));
    // 여기에 필요한 다른 DNS 헤더 정보 출력 추가 가능
}

void capture_packets() {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sockfd == -1) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }

    char buffer[MAX_PACKET_SIZE];

    while (1) {
        ssize_t bytesRead = recv(sockfd, buffer, MAX_PACKET_SIZE, 0);
        if (bytesRead == -1) {
            perror("Packet receive error");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        struct ip *ipHeader = (struct ip *)buffer;

        if (ipHeader->ip_p == IPPROTO_ICMP) {
            struct icmpheader *icmpHeader = (struct icmpheader *)(buffer + (ipHeader->ip_hl << 2));

            printf("\nReceived ICMP Packet\n");
            print_icmp_header(icmpHeader);
        } else if (ipHeader->ip_p == IPPROTO_UDP) {
            struct udphdr *udpHeader = (struct udphdr *)(buffer + (ipHeader->ip_hl << 2));

            // UDP 포트 53은 DNS 트래픽을 나타냄
            if (ntohs(udpHeader->uh_dport) == 53 || ntohs(udpHeader->uh_sport) == 53) {
                struct dnshdr *dnsHeader = (struct dnshdr *)(buffer + (ipHeader->ip_hl << 2) + sizeof(struct udphdr));

                printf("\nReceived DNS Packet\n");
                print_dns_header(dnsHeader);
            }
        }
    }

    close(sockfd);
}

int main() {
    printf("프로그램 시작");
    capture_packets();
    return 0;
}
