#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#define TCP 't'
#define UDP 'u'
#define ICMP 'i'
#define DNS 'd'
#define HTTP 'h'
#define SSH 's'
#define NONE 'n'

void menuPrint();
void menuManager();
void captureManager(char nt, char at);

int main() {
    menuManager();
    return 0;
}

void menuManager(){
    int menu = -1;
    while(1){
        menuPrint();
        scanf("%d", &menu);
        switch (menu) {
            case 1:
                captureManager(ICMP, NONE);
                break;
            case 2:
                captureManager(UDP, DNS);
                break;
            case 3:
                captureManager(TCP, HTTP);
                break;
            case 4:
                captureManager(TCP, SSH);
                break;
            case 5:

                break;
            case 0:
                exit(0);
            default:
                printf("존재하지 않는 기능입니다.\n");
        }
    }
}

void menuPrint(){
    printf("=========== 메뉴 ===========\n");
    printf("1. ICMP 패킷 분석\n");
    printf("2. DNS 패킷 분석\n");
    printf("3. HTTP 패킷 분석\n");
    printf("4. SSH 패킷 분석\n");
    printf("5. 화면 비우기\n");
    printf("0. 종료\n");
    printf("==========================\n");
    printf("메뉴 선택 : ");
}

void captureManager(char nt, char at){
    if(nt == ICMP){

    }else if(nt == UDP){

    }else if(nt == TCP){
        if(at == HTTP){

        }else if(at == SSH){

        }
    }
}