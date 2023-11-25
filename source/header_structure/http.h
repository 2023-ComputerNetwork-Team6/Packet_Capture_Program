#ifndef NETWORK_RAW_SOCKET_HTTP_H
#define NETWORK_RAW_SOCKET_HTTP_H

#define MAX_HEADER_NAME_LENGTH 50
#define MAX_HEADER_VALUE_LENGTH 100

//chat gpt
struct httpHeader{
    char name[MAX_HEADER_NAME_LENGTH];
    char value[MAX_HEADER_VALUE_LENGTH];
    struct HttpHeader *next;  // 다음 헤더 필드를 가리키는 포인터
};

#endif NETWORK_RAW_SOCKET_HTTP_H