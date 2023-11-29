#ifndef NETWORK_RAW_SOCKET_HTTP_H
#define NETWORK_RAW_SOCKET_HTTP_H

#define MAX_PACKET_SIZE 65536
#define MAX_HEADER_NAME_LENGTH 50
#define MAX_HEADER_VALUE_LENGTH 100

// HTTP 헤더 필드 구조체
struct httpHeader {
    char name[MAX_PACKET_SIZE];
    char value[MAX_PACKET_SIZE];
    struct httpHeader *next;  // 다음 헤더 필드를 가리키는 포인터
};

// HTTP 패킷 구조체
struct httpPacket {
    char message[MAX_PACKET_SIZE];  // HTTP 메서드 (GET, POST, 등) // HTTP 바디 (생략될 수 있음)
};

#endif NETWORK_RAW_SOCKET_HTTP_H