#ifndef NETWORK_RAW_SOCKET_TCP_H
#define NETWORK_RAW_SOCKET_TCP_H
#include <stdint.h>

// TCP 헤더 구조체 정의
struct tcpHeader {
    uint16_t source_port;      // 출발지 포트 번호
    uint16_t dest_port;        // 목적지 포트 번호
    uint32_t sequence_number;  // 시퀀스 번호
    uint32_t acknowledgment;  // 확인 응답 번호
    uint8_t data_offset;      // 데이터 오프셋 및 예약 필드
    uint8_t flags;            // 플래그 필드
    uint16_t window_size;     // 윈도우 크기
    uint16_t checksum;        // 체크섬
    uint16_t urgent_pointer;  // 긴급 포인터
};

#endif NETWORK_RAW_SOCKET_TCP_H