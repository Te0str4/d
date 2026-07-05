#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/types.h>

#define ETHERNET_LEN 14
#define HTTP_PRINT_LEN 100

// Ethernet Header 구조체
// 패킷의 가장 앞에 위치하며 src MAC, dst MAC, 상위 프로토콜 타입을 담고 있다.
struct ethernet_header {
    u_char dst_mac[6];       // destination MAC address
    u_char src_mac[6];       // source MAC address
    u_short type;            // protocol type, IPv4는 0x0800
};

// IP Header 구조체
// Ethernet Header 뒤에 위치하며 src IP, dst IP, protocol, IP header length를 담고 있다.
struct ip_header {
    unsigned char ihl:4;     // IP header length, 4바이트 단위
    unsigned char version:4; // IP version
    unsigned char tos;       // type of service
    unsigned short total_len;// IP packet 전체 길이
    unsigned short id;       // identification
    unsigned short flag_offset;
    unsigned char ttl;       // time to live
    unsigned char protocol;  // TCP, UDP, ICMP 등을 구분
    unsigned short checksum; // IP checksum
    struct in_addr src_ip;   // source IP address
    struct in_addr dst_ip;   // destination IP address
};

// TCP Header 구조체
// IP Header 뒤에 위치하며 src port, dst port, TCP header length를 확인할 수 있다.
struct tcp_header {
    u_short src_port;        // source port
    u_short dst_port;        // destination port
    u_int seq;               // sequence number
    u_int ack;               // acknowledgement number
    u_char offset_reserved;  // TCP header length 정보가 들어있는 필드
    u_char flags;            // TCP flags
    u_short window;          // window size
    u_short checksum;        // TCP checksum
    u_short urgent;          // urgent pointer
};

// TCP Header 길이를 계산하는 매크로
// offset_reserved의 상위 4비트가 TCP header length이고, 4바이트 단위라서 4를 곱한다.
#define TCP_HEADER_LEN(tcp) (((tcp)->offset_reserved >> 4) * 4)

// MAC 주소 출력 함수
// MAC 주소는 6바이트 배열이므로 각 바이트를 16진수로 출력한다.
void print_mac(const u_char mac[6])
{
    printf("%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Payload 내용을 출력하는 함수
// 너무 길게 출력되지 않도록 앞부분만 출력한다.
void print_payload(const u_char *payload, int payload_len)
{
    int i;
    int len = payload_len;

    if (len > HTTP_PRINT_LEN) {
        len = HTTP_PRINT_LEN;
    }

    for (i = 0; i < len; i++) {
        if (payload[i] == '\n' || payload[i] == '\r' || payload[i] == '\t') {
            putchar(payload[i]);
        } else if (isprint(payload[i])) {
            putchar(payload[i]);
        } else {
            putchar('.');
        }
    }

    printf("\n");
}

// Payload가 평문 HTTP 메시지처럼 보이는지 확인하는 함수
// GET, POST, HEAD, PUT, HTTP/ 등으로 시작하면 HTTP 메시지로 판단한다.
int is_http_payload(const u_char *payload, int payload_len)
{
    if (payload_len < 4) {
        return 0;
    }

    if (!memcmp(payload, "GET ", 4) ||
        !memcmp(payload, "POST ", 5) ||
        !memcmp(payload, "HEAD ", 5) ||
        !memcmp(payload, "PUT ", 4) ||
        !memcmp(payload, "HTTP/", 5)) {
        return 1;
    }

    return 0;
}

// 패킷이 캡처될 때마다 실행되는 callback 함수
// Ethernet Header, IP Header, TCP Header, Payload를 순서대로 분석한다.
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    struct ethernet_header *eth;
    struct ip_header *ip;
    struct tcp_header *tcp;

    int ip_header_len;
    int tcp_header_len;
    int ip_total_len;
    int payload_len;
    int payload_offset;

    const u_char *payload;

    // args는 사용하지 않으므로 경고를 없애기 위해 처리한다.
    (void)args;

    // Ethernet Header보다 짧은 패킷은 분석할 수 없다.
    if (header->caplen < ETHERNET_LEN) {
        return;
    }

    // packet의 시작 위치는 Ethernet Header이다.
    eth = (struct ethernet_header *)packet;

    // IPv4 패킷
