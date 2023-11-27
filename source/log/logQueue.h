#ifndef NETWORK_RAW_SOCKET_LOG_QUEUE_H
#define NETWORK_RAW_SOCKET_LOG_QUEUE_H

#include <stddef.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>

#define MAX_QUEUE_SIZE 2000
#define MAX_DATA_SIZE 51

struct LogQueueNode{
    char data[MAX_DATA_SIZE];
    struct LogQueueNode* rigth;
};

struct LogQueue{
    unsigned int size;
    unsigned int maxSize;
    struct LogQueueNode* front;
    struct LogQueueNode* rear;
};

void initialize(struct LogQueue* q, int max_size){
    if(max_size < 1){
        q->size = 1;
        q->maxSize = MAX_QUEUE_SIZE;
        q->front = NULL;
        q->rear = NULL;
    }else{
        q->size = 1;
        q->maxSize = max_size;
        q->front = NULL;
        q->rear = NULL;
    }
};

void enqueue(struct LogQueue* q, const char* data){
    if(q->size >= q->maxSize){
        return;
    }

    struct LogQueueNode* newLog = (struct LogQueueNode*)malloc(sizeof(struct LogQueueNode));
    if(newLog == NULL){
        printf("[오류] 패킷 분석 내용을 로그 안에 추가하던 중 할당 오류가 발생하였습니다.\n프로그램을 강제종료합니다.");
        exit(1);
    }

    strncpy(newLog->data, data, MAX_DATA_SIZE-1);
    newLog->data[MAX_DATA_SIZE-1]='\0';
    newLog->rigth = NULL;

    if(q->front == NULL){
        q->front = newLog;
        q->rear = newLog;
    }else{
        q->rear->rigth = newLog;
        q->rear = newLog;
    }

    q->size++;
}

char* dequeue(struct LogQueue* q){
    if(q->front == NULL)
        return NULL;

    struct LogQueueNode* frontLog = q->front;
    char* data = frontLog->data;
    if(frontLog == q->rear){
        q->front = NULL;
        q->rear = NULL;
    }else
        q->front = frontLog->rigth;
    free(frontLog);
    q->size--;
    return data;
}

void clear(struct LogQueue* q){
    while(q->front != NULL)
        dequeue(q);
}

#endif NETWORK_RAW_SOCKET_LOG_QUEUE_H