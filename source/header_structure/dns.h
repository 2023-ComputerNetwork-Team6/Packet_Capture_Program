#ifndef NETWORK_RAW_SOCKET_DNS_H
#define NETWORK_RAW_SOCKET_DNS_H

struct dnsHeader{
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

struct dnsPacket {
    struct dnsHeader* dnsHeader;
    char* data;
    int dataSize;
};

#endif NETWORK_RAW_SOCKET_DNS_H