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

    // IPv4 패킷만 처리한다.
    // Ethernet type이 0x0800이면 IPv4이다.
    if (ntohs(eth->type) != 0x0800) {
        return;
    }

    // IP Header는 Ethernet Header 바로 뒤에 위치한다.
    ip = (struct ip_header *)(packet + ETHERNET_LEN);

    // 과제 조건에 따라 TCP 패킷만 처리한다.
    if (ip->protocol != IPPROTO_TCP) {
        return;
    }

    // IP Header 길이 계산
    // ihl은 4바이트 단위이므로 실제 길이는 ihl * 4이다.
    ip_header_len = ip->ihl * 4;

    if (ip_header_len < 20) {
        return;
    }

    // TCP Header는 Ethernet Header + IP Header 뒤에 위치한다.
    tcp = (struct tcp_header *)(packet + ETHERNET_LEN + ip_header_len);

    // TCP Header 길이 계산
    tcp_header_len = TCP_HEADER_LEN(tcp);

    if (tcp_header_len < 20) {
        return;
    }

    // IP 패킷 전체 길이
    // 네트워크 바이트 순서이므로 ntohs()로 변환한다.
    ip_total_len = ntohs(ip->total_len);

    // Payload 시작 위치 계산
    payload_offset = ETHERNET_LEN + ip_header_len + tcp_header_len;

    // Payload 길이 계산
    payload_len = ip_total_len - ip_header_len - tcp_header_len;

    if (payload_len < 0) {
        return;
    }

    // 캡처된 길이보다 payload 위치가 뒤에 있으면 잘못된 패킷이므로 무시한다.
    if (header->caplen < (bpf_u_int32)payload_offset) {
        return;
    }

    // 실제 캡처된 payload 길이에 맞게 보정한다.
    if (payload_len > (int)header->caplen - payload_offset) {
        payload_len = (int)header->caplen - payload_offset;
    }

    // Payload는 전체 헤더 뒤에 위치한다.
    payload = packet + payload_offset;

    printf("\n========== Packet ==========\n");

    // Ethernet Header 정보 출력
    printf("[Ethernet Header]\n");
    printf("src MAC : ");
    print_mac(eth->src_mac);
    printf("\n");

    printf("dst MAC : ");
    print_mac(eth->dst_mac);
    printf("\n");

    // IP Header 정보 출력
    printf("[IP Header]\n");
    printf("src IP  : %s\n", inet_ntoa(ip->src_ip));
    printf("dst IP  : %s\n", inet_ntoa(ip->dst_ip));
    printf("IP Header Length : %d bytes\n", ip_header_len);

    // TCP Header 정보 출력
    // 포트 번호는 네트워크 바이트 순서이므로 ntohs()로 변환한다.
    printf("[TCP Header]\n");
    printf("src Port : %d\n", ntohs(tcp->src_port));
    printf("dst Port : %d\n", ntohs(tcp->dst_port));
    printf("TCP Header Length : %d bytes\n", tcp_header_len);

    // HTTP Message 또는 Payload 출력
    printf("[HTTP Message]\n");

    if (payload_len <= 0) {
        printf("No payload\n");
    } else if (is_http_payload(payload, payload_len)) {
        print_payload(payload, payload_len);
    } else {
        printf("Payload exists, but it is not plain HTTP data. size = %d bytes\n",
               payload_len);
    }
}

int main(int argc, char *argv[])
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;

    char filter_exp[] = "tcp";  // TCP 패킷만 캡처하기 위한 필터
    char *dev = "enp0s3";       // VirtualBox Ubuntu에서 사용하는 인터페이스 이름
    bpf_u_int32 net = 0;

    // 실행할 때 인터페이스 이름을 인자로 받으면 그 값을 사용한다.
    if (argc >= 2) {
        dev = argv[1];
    }

    // 네트워크 인터페이스를 연다.
    // 세 번째 인자 1은 promiscuous mode를 의미한다.
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("pcap_open_live error: %s\n", errbuf);
        return 1;
    }

    // tcp 필터를 컴파일한다.
    if (pcap_compile(handle, &filter, filter_exp, 0, net) == -1) {
        printf("pcap_compile error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    // 컴파일한 필터를 실제 캡처 핸들에 적용한다.
    if (pcap_setfilter(handle, &filter) == -1) {
        printf("pcap_setfilter error: %s\n", pcap_geterr(handle));
        pcap_freecode(&filter);
        pcap_close(handle);
        return 1;
    }

    printf("Start capture on interface: %s\n", dev);
    printf("Filter: %s\n", filter_exp);

    // 패킷 캡처를 시작한다.
    // 패킷이 잡힐 때마다 got_packet() 함수가 호출된다.
    pcap_loop(handle, -1, got_packet, NULL);

    // 사용한 자원을 정리한다.
    pcap_freecode(&filter);
    pcap_close(handle);

    return 0;
}
