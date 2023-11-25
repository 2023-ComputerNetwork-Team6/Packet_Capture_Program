#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <ctype.h>
#include "log/logQueue.h"
#include "header_structure/dns.h"
#include "header_structure/ssh.h"
#include "header_structure/http.h"

#define TCP 't'
#define UDP 'u'
#define ICMP 'i'
#define DNS 'd'
#define HTTP 'h'
#define SSH 's'
#define NONE 'n'

#define MAX_PACKET_SIZE 65536
#define MAX_FILE_NAME 30
#define INIT_QUEUE_SIZE 0

void menuManager();
void menuPrint();

void* captureThread(void* arg);

void captureManager(struct LogQueue* q, char* buf, int size);
int ethernetCapture(struct LogQueue* q, struct ethhdr* eh);
int* ipCapture(struct LogQueue* q, struct iphdr* iph);
void tcpCapture(struct LogQueue* q, struct tcphdr* th);
void udpCapture(struct LogQueue* q, struct udphdr* uh);
void icmpCapture(struct LogQueue* q, struct icmphdr* ih);
void dnsCapture(struct LogQueue* q, struct dnsHeader* dh);
void httpCapture(struct LogQueue* q, struct httpHeader* hh);
void sshCapture(struct LogQueue* q, struct sshHeader* sh);

void saveCaptureManager();
void saveCapture(char* fn);

int recvStatus = 1;
struct LogQueue lq;

int main() {
    initialize(&lq, INIT_QUEUE_SIZE);
    printf("******* Packet Capture Program *******\n");
    printf("[자세한 작동 방식은 사용법을 참조하세요.]\n");
    menuManager();
    return 0;
}

void menuManager(){
    int menu = -1;
    int rs;
    pthread_t ct;
    while(1){
        recvStatus = 1;
        menuPrint();
        scanf("%d", &menu);
        scanf("%*c");           //버퍼 비우기
        switch (menu) {
            case 1:
                recvStatus = 1;
                if((rs = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1){
                    printf("[오류] raw socket 생성에 실패했습니다. 프로그램을 종료합니다.");
                    exit(1);
                }
                ct = pthread_create(&ct, NULL, captureThread, (void *)&rs);
                pthread_detach(ct);
                break;
            case 2:
                recvStatus = 0;
                saveCaptureManager();
                break;
            case 3:
                system("clear");
                break;
            case 9:
                printf("[주의] 해당 기능을 사용할 시 기존에 저장된 분석 결과는 삭제됩니다.\n계속 진행하시겠습니까? [y/n] ");
                int answer = getchar();
                if(answer == 'y'){
                    clear(&lq);
                    printf("* 0 이하의 값을 입력하시면 초기 사이즈(2000줄) 설정으로 돌아갑니다.\n   [현재 사이즈 : %d줄]\n", lq.maxSize);
                    printf("입력 값 : ");
                    scanf(" %d", &answer);
                    if(isdigit(answer)){
                        initialize(&lq, answer);
                    }else{
                        printf("[오류] 입력값이 숫자가 아닙니다.\n");
                    }
                }
                break;
            case 0:
                exit(0);
            default:
                printf("존재하지 않는 기능입니다.\n");
        }
    }
}

void menuPrint(){
    printf("============ 메뉴 ============\n");
    printf("1. 패킷 분석\n");
    printf("2. 분석 종료\n");
    printf("3. 화면 비우기\n");
    printf("9. 최대 임시 저장 줄 설정\n");
    printf("0. 종료\n");
    printf("=============================\n");
    printf("메뉴 선택 : ");
}

void* captureThread(void* arg){
    int rs =*(int*)arg;
    char *buf = (char *) malloc(MAX_PACKET_SIZE);
    int data = 1;
    while(recvStatus){
        data = recvfrom(rs, buf, MAX_PACKET_SIZE, 0, NULL, NULL);
        if(data == -1){
            printf("[오류] 데이터를 수신과정에서 오류가 발생했습니다.\n패킷 분석을 강제종료합니다.");
            pthread_exit(NULL);
        }
        captureManager(&lq, buf, data);
    }

    free(buf);
}

void captureManager(struct LogQueue* q, char* buf, int size){
    struct ethhdr* ethernetHeader = (struct ethhdr*)buf;

    int ethernetType;
    if((ethernetType = ethernetCapture(&lq, ethernetHeader) == ETH_P_IP)){
        struct iphdr* ipHeader = (struct iphdr*)(buf + ETH_HLEN);
    }else if(ethernetHeader == ETH_P_IPV6){
        struct ip6_hdr* ip6Header = (struct ip6_hdr*)(buf  + ETH_HLEN);
    }


}

void saveCaptureManager(){
    printf("분석 내용을 저장하시겠습니까? [y/n] ");
    int answer;
    while(1){
        answer = getchar();
        if(answer == 'y'){
            char name[MAX_FILE_NAME];
            printf("파일 이름을 입력해주세요 : ");
            scanf(" %s", name);
            saveCapture(name);
            break;
        }else if(answer == 'n'){
            break;
        }else{
            printf("다시 입력해주세요.\n");
        }
    }
}

void saveCapture(char* fn){
    char fileName[MAX_FILE_NAME + 5];
    char* txt = ".txt";
    strcat(fileName, fn);
    strcat(fileName, txt);
    FILE* captureLog = fopen(fileName, "w");
    if(captureLog == NULL){
        printf("[오류] 파일을 저장할 수 없습니다.\n프로그램을 강제종료합니다.\n");
        return;
    }
    unsigned int size = lq.size;

    printf("%s 파일을 저장하는 중입니다.\n\n[전체 %d 줄]\n", fileName, size);
    while(lq.front == NULL){
        char* data = strdup(lq.front->data);
        fprintf(captureLog, "%s\n", data);
    }
    fclose(captureLog);
    printf("%s 파일을 저장했습니다.\n", fileName);
}