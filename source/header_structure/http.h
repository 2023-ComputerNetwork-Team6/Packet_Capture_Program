#ifndef NETWORK_RAW_SOCKET_HTTP_H
#define NETWORK_RAW_SOCKET_HTTP_H

#define MAX_HEADER_NAME_LENGTH 50
#define MAX_HEADER_VALUE_LENGTH 100

// HTTP 헤더 필드 구조체
struct httpHeader {
    char name[MAX_HEADER_NAME_LENGTH];
    char value[MAX_HEADER_VALUE_LENGTH];
    struct httpHeader *next;  // 다음 헤더 필드를 가리키는 포인터
};

// HTTP 패킷 구조체
struct httpPacket {
    char method[MAX_HEADER_NAME_LENGTH];  // HTTP 메서드 (GET, POST, 등)
    char path[MAX_HEADER_VALUE_LENGTH];    // 요청 경로 또는 응답 상태
    char version[MAX_HEADER_VALUE_LENGTH]; // HTTP 버전
    struct httpHeader *headers;            // HTTP 헤더 필드들의 연결 리스트
    char *body;                           // HTTP 바디 (생략될 수 있음)
};

#endif NETWORK_RAW_SOCKET_HTTP_H