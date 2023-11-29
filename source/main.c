#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "log/logQueue.h"

#define IP 8
#define TCP 6
#define UDP 17
#define ICMP 1
#define DNS 53
#define HTTP 80
#define SSH 22

#define MAX_PACKET_SIZE 65536
#define MAX_FILE_NAME 30
#define INIT_QUEUE_SIZE 0
#define ASCCI_START_NUM 32
#define ASCCI_END_NUM 128
#define HEX 16

enum {
    red = 1,
    yellow = 3,
    blue = 4
};

void menuManager();
void menuPrint();

void* captureThread(void* arg);

void captureManager(struct LogQueue* q, char* buf);
void ethernetCapture(struct LogQueue* q, struct ethhdr* eh);
void ipCapture(struct LogQueue* q, struct iphdr* iph);
void tcpCapture(struct LogQueue* q, struct tcphdr* th);
void udpCapture(struct LogQueue* q, struct udphdr* uh);
void icmpCapture(struct LogQueue* q, struct icmphdr* ih);
void printApplicationLayerProtocol(struct LogQueue* q, int p);
void hexChangeToAscii(struct LogQueue* q, unsigned char* pl, int len);

void saveCaptureManager();
void saveCapture(char* fn);

int recvStatus = 0;
struct LogQueue lq;

int main() {
    initializeLogQueue(&lq, INIT_QUEUE_SIZE);
    system("clear");
    printf("***************  Packet Capture Program  ***************\n");
    printf("\n\033[0;3%dm - 버전 : 1.0.0\n - 가동 가능 환경 : Linux\n - 권장 운영체제 : Ubuntu \n - 현재 로그 파일 저장 위치 : 프로그램 설치 폴더\n - 자세한 작동 방식은 사용법을 참조하세요.\033[0m\n\n", yellow);
    menuManager();
    return 0;
}

void menuManager(){
    int menu = -1;
    int rs;
    int start = 0;
    pthread_t ct;
    while(1){
        if(lq.front != NULL){
            printf("\n임시 저장 데이터가 존재합니다!\n");
        }
        menuPrint();
        scanf("%d", &menu);
        scanf("%*c");           //버퍼 비우기
        switch (menu) {
            case 1:
                start = 1;
                recvStatus = 1;
                if((rs = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1){
                    printf("[ \033[0;3%dm오류\033[0m ] raw socket 생성에 실패했습니다. 프로그램을 종료합니다.", red);
                    exit(1);
                }
                ct = pthread_create(&ct, NULL, captureThread, (void *)&rs);
                pthread_detach(ct);
                break;
            case 2:
                if(start == 0){
                    printf("분석한 패킷의 내용이 존재하지 않습니다.\n");
                    break;
                }
                recvStatus = 0;
                saveCaptureManager();
                break;
            case 3:
                system("clear");
                break;
            case 9:
                if(recvStatus == 1){
                    printf("[ \033[0;3%dm!경고!\033[0m ] 패킷 분석 도중에는 해당 기능을 이용하실 수 없습니다.", red);
                    break;
                }
                printf("[ \033[0;3%dm주의\033[0m ] 해당 기능을 사용할 시 기존에 저장된 분석 결과는 삭제됩니다.\n계속 진행하시겠습니까? [y/n] ", yellow);
                int answer = getchar();
                if(answer == 'y'){
                    clear(&lq);
                    printf("\033[0;3%dm* 0 이하의 값을 입력하시면 초기 사이즈(%d줄) 설정으로 돌아갑니다.\n* 임시 저장공간이 꽉차도 분석이 중단되지 않습니다!\033[0m\n\t[ \033[0;3%dm현재 사이즈 : %d줄\033[0m ]\n",yellow, MAX_QUEUE_SIZE, blue, lq.maxSize);
                    printf("입력 값 : ");
                    scanf(" %d", &answer);
                    initializeLogQueue(&lq, answer);
                }
                break;
            case 0:
                close(rs);

                exit(0);
            default:
                printf("존재하지 않는 기능입니다.\n");
        }
    }
}

void menuPrint(){
    printf("========================= 메뉴 =========================\n");
    printf("1. 패킷 분석\n");
    printf("2. 분석 종료 및 결과 저장\n");
    printf("3. 화면 비우기\n");
    printf("9. 최대 임시 저장 줄 설정\n");
    printf("\033[0;3%dm0. 종료\033[0m\n", red);
    printf("========================================================\n");
    printf("메뉴 선택 : ");
}

void* captureThread(void* arg){
    int rs =*(int*)arg;
    char *buf = (char *) malloc(MAX_PACKET_SIZE);
    int data = 1;
    while(recvStatus){
        data = recvfrom(rs, buf, MAX_PACKET_SIZE, 0, NULL, NULL);
        if(data == -1){
            printf("[ \033[0;3%dm오류\033[0m ] 데이터를 수신과정에서 오류가 발생했습니다.\n패킷 분석을 강제종료합니다.", yellow);
            pthread_exit(NULL);
        }
        captureManager(&lq, buf);
    }

    free(buf);
}

void captureManager(struct LogQueue* q, char* buf){
    struct ethhdr* ethernetHeader = (struct ethhdr*)buf;
    ethernetCapture(q, ethernetHeader);

    if(ethernetHeader->h_proto == IP){
        struct iphdr* ipHeader = (struct iphdr*)(buf + ETH_HLEN);
        int ipHeaderLength = (ipHeader->ihl*4);
        int overloadLength = ETH_HLEN + ipHeaderLength;
        int ipTotalLength = ntohs(ipHeader->tot_len);
        ipCapture(q, ipHeader);

        if(ipHeader->protocol == ICMP){
            struct icmphdr* icmpHeader = (struct icmphdr*)(buf + overloadLength);
            icmpCapture(q, icmpHeader);
        }else if(ipHeader->protocol == TCP){
            struct tcphdr* tcpHeader = (struct tcphdr*)(buf + overloadLength);
            tcpCapture(q, tcpHeader); // TCP 헤더 분석 함수 호출
            uint16_t sourcePort = ntohs(tcpHeader->th_sport);
            uint16_t destPort = ntohs(tcpHeader->th_dport);
            int tcpHeaderLength = (tcpHeader->th_off*4);
            int payloadLen = ipTotalLength - ipHeaderLength - tcpHeaderLength;
            if(sourcePort == HTTP || destPort == HTTP){
                printApplicationLayerProtocol(q, HTTP);
                hexChangeToAscii(q, buf + overloadLength + tcpHeaderLength, payloadLen);
            }else if(sourcePort == SSH || destPort == SSH) {
                printApplicationLayerProtocol(q, SSH);
                hexChangeToAscii(q, buf+overloadLength+tcpHeaderLength, payloadLen);
            }
        }else if(ipHeader->protocol == UDP){
            struct udphdr* udpHeader = (struct udphdr*)(buf + overloadLength);
            udpCapture(&lq, udpHeader); // UDP 헤더 분석 함수 호출
            uint16_t sourcePort = ntohs(udpHeader->uh_sport);
            uint16_t destPort = ntohs(udpHeader->uh_dport);
            int udpPacketLength = ntohs(udpHeader->uh_ulen);
            int udpHeaderLength = sizeof(struct udphdr);
            int payloadLength = udpPacketLength - udpHeaderLength;
            if(sourcePort == DNS || destPort == DNS) {
                printApplicationLayerProtocol(q, DNS);
                hexChangeToAscii(q, buf + overloadLength + udpHeaderLength, payloadLength);
            }
        }
    }
}

void ethernetCapture(struct LogQueue* q, struct ethhdr* eh){
    char etherBuf[MAX_DATA_SIZE] = {0};
    snprintf(etherBuf, sizeof(etherBuf), "\n\n[Ethernet Header]\n");
    enqueue(q, etherBuf);
    printf("%s", etherBuf);

    snprintf(etherBuf, sizeof(etherBuf), " - Source MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", eh->h_source[0], eh->h_source[1], eh->h_source[2], eh->h_source[3], eh->h_source[4], eh->h_source[5]);
    enqueue(q, etherBuf);
    printf("%s", etherBuf);

    snprintf(etherBuf, sizeof(etherBuf)," - Dest MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", eh->h_dest[0], eh->h_dest[1], eh->h_dest[3], eh->h_dest[4], eh->h_dest[5]);
    enqueue(q, etherBuf);
    printf("%s", etherBuf);
}

void ipCapture(struct LogQueue* q, struct iphdr* iph){
    char ipBuf[MAX_DATA_SIZE]={0};
    struct in_addr s, d;
    s.s_addr = iph->saddr;
    d.s_addr = iph->daddr;

    snprintf(ipBuf, sizeof(ipBuf), "[IP Header]\n");
    enqueue(q, ipBuf);
    printf("%s", ipBuf);

    snprintf(ipBuf, sizeof(ipBuf), " - Version : IPv%d\n", iph->version);
    enqueue(q, ipBuf);
    printf("%s", ipBuf);

    snprintf(ipBuf, sizeof(ipBuf), " - IP Header Length : %d\n", iph->ihl*4);
    enqueue(q, ipBuf);
    printf("%s", ipBuf);

    snprintf(ipBuf, sizeof(ipBuf), " - Protocol : %d\n", iph->protocol);
    enqueue(q, ipBuf);
    printf("%s", ipBuf);

    snprintf(ipBuf, sizeof(ipBuf), " - Checksum : %d\n", iph->check);
    enqueue(q, ipBuf);
    printf("%s", ipBuf);

    snprintf(ipBuf, sizeof(ipBuf), " - Source IP : %s\n", inet_ntoa(s));
    enqueue(q, ipBuf);
    printf("%s", ipBuf);

    snprintf(ipBuf, sizeof(ipBuf), " - Dest IP : %s\n", inet_ntoa(d));
    enqueue(q, ipBuf);
    printf("%s", ipBuf);
}

void icmpCapture(struct LogQueue* q, struct icmphdr* ih){
    char icmpBuf[MAX_DATA_SIZE]={0};

    snprintf(icmpBuf, sizeof(icmpBuf), "[ICMP Header]\n");
    enqueue(q, icmpBuf);
    printf("%s", icmpBuf);

    snprintf(icmpBuf, sizeof(icmpBuf), " - Type : %d\n", ih->type);
    enqueue(q, icmpBuf);
    printf("%s", icmpBuf);

    snprintf(icmpBuf, sizeof(icmpBuf), " - Code : %d\n", ih->code);
    enqueue(q, icmpBuf);
    printf("%s", icmpBuf);

    snprintf(icmpBuf, sizeof(icmpBuf), " - Checksum : %d\n", ih->checksum);
    enqueue(q, icmpBuf);
    printf("%s", icmpBuf);
}

void tcpCapture(struct LogQueue* q, struct tcphdr* th) {
    char tcpBuf[MAX_DATA_SIZE]={0};
    snprintf(tcpBuf, sizeof(tcpBuf), "[TCP Header]\n");
    enqueue(q, tcpBuf);
    printf("%s", tcpBuf);

    uint16_t sourcePort = ntohs(th->th_sport);
    uint16_t destPort = ntohs(th->th_dport);
    uint32_t seqNumber = ntohl(th->th_seq);
    uint32_t ackNumber = ntohl(th->th_ack);
    uint16_t checksum = ntohs(th->th_sum);


    snprintf(tcpBuf, sizeof(tcpBuf), " - Source Port: %u\n", sourcePort);
    enqueue(q, tcpBuf);
    printf("%s", tcpBuf);

    snprintf(tcpBuf, sizeof(tcpBuf), " - Destination Port: %u\n", destPort);
    enqueue(q, tcpBuf);
    printf("%s", tcpBuf);


    snprintf(tcpBuf, sizeof(tcpBuf), " - Seq Number: %u\n", seqNumber);
    enqueue(q, tcpBuf);
    printf("%s", tcpBuf);

    snprintf(tcpBuf, sizeof(tcpBuf), " - Ack Number: %u\n", ackNumber);
    enqueue(q, tcpBuf);
    printf("%s", tcpBuf);

    snprintf(tcpBuf, sizeof(tcpBuf), " - Checksum: %u\n", checksum);
    enqueue(q, tcpBuf);
    printf("%s", tcpBuf);
}

void udpCapture(struct LogQueue* q, struct udphdr* uh) {
    char udpBuf[MAX_DATA_SIZE]={0};
    snprintf(udpBuf, sizeof(udpBuf), "[UDP Header]\n");
    enqueue(q, udpBuf);
    printf("%s", udpBuf);

    uint16_t sourcePort = ntohs(uh->uh_sport);
    uint16_t destPort = ntohs(uh->uh_dport);
    uint16_t length = ntohs(uh->uh_ulen);
    uint16_t checksum = ntohs(uh->uh_sum);


    snprintf(udpBuf, sizeof(udpBuf), " - Source Port: %u\n", sourcePort);
    enqueue(q, udpBuf);
    printf("%s", udpBuf);

    snprintf(udpBuf, sizeof(udpBuf), " - Destination Port: %u\n", destPort);
    enqueue(q, udpBuf);
    printf("%s", udpBuf);

    snprintf(udpBuf, sizeof(udpBuf), " - Length: %u\n", length);
    enqueue(q, udpBuf);
    printf("%s", udpBuf);

    snprintf(udpBuf, sizeof(udpBuf), " - Checksum: %u\n", checksum);
    enqueue(q, udpBuf);
    printf("%s", udpBuf);
}

void printApplicationLayerProtocol(struct LogQueue* q, int p){
    switch (p) {
        case DNS :
            enqueue(q, "[DNS]\n");
            printf("[DNS]\n");
            break;
        case HTTP :
            enqueue(q, "[HTTP]\n");
            printf("[HTTP]\n");
            break;
        case SSH :
            enqueue(q, "[SSH]\n");
            printf("[SSH]\n");
            break;
    }
}

void hexChangeToAscii(struct LogQueue* q, unsigned char* pl, int len){
    char buf[MAX_DATA_SIZE]={0};
    char temp[MAX_DATA_SIZE]={0};
    for (int i = 0; i < len; i++) {
        strcat(buf, "\t\t");
        if (i != 0 && i % HEX == 0) {
            for (int j = i - HEX; j < i; j++) {
                if (pl[j] >= ASCCI_START_NUM && pl[j] < ASCCI_END_NUM){
                    sprintf(temp, "%c", pl[j]);
                    strncat(buf, temp, 1);
                }else
                    strcat(buf, ".");
            }
            strcat(buf, "\n");
            enqueue(q, buf);
            printf("%s", buf);
            memset(buf, '\0', sizeof(buf));
        }
        if (i % 16 == 0)
            strcat(buf, "\t");
        sprintf(temp, "%02X", (unsigned int)pl[i]);
        if (i == len - 1){
            for (int j = 0; j < ((HEX - 1) - (i % HEX)); j++)
                strcat(buf, "   ");
            strcat(buf, "\t\t");
            for (int j = (i - (i % HEX)); j <= i; j++){
                if (pl[j] >= ASCCI_START_NUM && pl[j] < ASCCI_END_NUM){
                    sprintf(temp, "%c", pl[j]);
                    strncat(buf, temp, 1);
                }
                else
                    strcat(buf, ".");
            }
            strcat(buf, "\n");
            enqueue(q, buf);
            printf("%s", buf);
            memset(buf, '\0', sizeof(buf));
        }
    }
}

void saveCaptureManager(){
    printf("분석 내용을 저장하시겠습니까? [y/n] ");
    int answer;
    while(1){
        answer = getchar();
        if(answer == 'y' | answer == 'Y'){
            char name[MAX_FILE_NAME];
            printf("파일 이름을 입력해주세요 : ");
            scanf(" %s", name);
            saveCapture(name);
            break;
        }else if(answer == 'n' | answer == 'Y'){
            break;
        }else{
            printf("다시 입력해주세요.\n");
        }
    }
}

void saveCapture(char* fn){
    char fileName[MAX_FILE_NAME + 5] ={0};
    char* txt = ".txt";
    strcat(fileName, fn);
    strcat(fileName, txt);
    FILE* captureLog = fopen(fileName, "w");
    if(captureLog == NULL){
        printf("[ \033[0;3%dm오류\033[0m ] 파일을 저장할 수 없습니다.\n프로그램을 강제종료합니다.\n", yellow);
        return;
    }
    unsigned int size = lq.size;

    printf("%s 파일을 저장하는 중입니다.\n\n[ \033[0;3%dm전체 %d 줄\033[0m ]\n", fileName, blue, size);
    while(lq.front != NULL){
        char* data = strdup(dequeue(&lq));
        fprintf(captureLog, "%s\n", data);
    }
    fclose(captureLog);
    printf("%s 파일을 저장했습니다.\n", fileName);
}