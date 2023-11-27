#ifndef NETWORK_RAW_SOCKET_UDP_H
#define NETWORK_RAW_SOCKET_UDP_H

#include <stdint.h>

// UDP 헤더 구조체 정의
struct udpHeader {
    uint16_t source_port;      // 출발지 포트 번호
    uint16_t dest_port;        // 목적지 포트 번호
    uint16_t length;           // 길이
    uint16_t checksum;        // 체크섬
};

#endif NETWORK_RAW_SOCKET_UDP_H