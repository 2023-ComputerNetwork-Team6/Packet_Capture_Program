#ifndef NETWORK_RAW_SOCKET_IP_H
#define NETWORK_RAW_SOCKET_IP_H

#include <stdint.h>

// IP 헤더 구조체 정의
struct ipHeader {
    uint8_t version_header_length;  // 버전 및 헤더 길이
    uint8_t type_of_service;        // 서비스 유형
    uint16_t total_length;          // 전체 길이
    uint16_t identification;        // 식별자
    uint16_t flags_fragment_offset; // 플래그와 프래그먼트 오프셋
    uint8_t time_to_live;           // TTL
    uint8_t protocol;               // 프로토콜
    uint16_t header_checksum;       // 헤더 체크섬
    uint32_t source_ip;             // 출발지 IP 주소
    uint32_t dest_ip;               // 목적지 IP 주소
};

#endif NETWORK_RAW_SOCKET_IP_H