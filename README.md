# PACP-Programming
```c
#include <arpa/inet.h>      // 인터넷 주소
#include <netinet/ether.h>  // 이더넷 프레임
#include <netinet/ip.h>     // IP 패킷
#include <netinet/tcp.h>    // TCP 세그먼트
#include <pcap.h>           // libpcap
#include <stdio.h>

int packet_count = 0;
```

코드 구성에 필요한 라이브러리들을 include 해주었고 패킷 개수를 세는 packet_count를 전역 변수로 설정해주었습니다.

### main 함수 분석

```c
int main() {
    pcap_t *handle;                 // 패킷 캡처
    char errbuf[PCAP_ERRBUF_SIZE];  // 오류 메시지 저장
    pcap_if_t *all_devices, *selected_device;
    char *dev;

    if (pcap_findalldevs(&all_devices, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return 1;
    }

    for (selected_device = all_devices; selected_device != NULL; selected_device = selected_device->next) {
        dev = selected_device->name;
        if (dev != NULL) {
            break;
        }
    }

    if (dev == NULL) {
        printf("No devices found.\n");
        return 1;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 1;
    }

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
```

먼저, 패킷 캡처와 오류 처리를 위한 변수들을 선언해주었습니다.

시스템에 연결된 모든 네트워크 장치를 검색하기 위해 pcap_findalldevs 함수를 사용하였고 반복하며 첫 번째 장치를 선택하게끔 하였습니다.

선택된 장치가 없을 경우 No devices found 를 출력하도록 하였고, 장치를 열어 패킷 캡처를 하는데 실패할 경우 에러 메시지를 출력하도록 하였습니다.

그 후 메모리 누수 방지를 위해 네트워크 장치를 pcap_close 함수를 통해 닫아주었습니다.

### packet_handler 함수 분석

```c
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header;  // 이더넷 프레임 헤더 (<netinet/ether.h>)
    struct ip *ip_header;             // IP 프로토콜 헤더 (<netinet/ip.h>)
    struct tcphdr *tcp_header;        // TCP 세그먼트 헤더 (<netinet/tcp.h>)
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    int ip_header_length;

    eth_header = (struct ether_header *)packet;  // 패킷의 시작을 가리킴
```

packet_hadler 함수에서는 먼저 이더넷 프레임, IP 헤더, TCP 헤더를 가져올 수 있도록 변수들을 선언해주었습니다.

```c
if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
    ip_header = (struct ip *)(packet + ETHER_HDR_LEN);

    if (ip_header->ip_p == IPPROTO_TCP) {
        packet_count++;  // TCP 패킷을 받을 때마다 카운터 증가
        printf("Packet Info %d\n", packet_count);

        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

        // 이더넷 헤더
        printf("- Ethernet Header\n");
        printf("   - src mac: %s\n", ether_ntoa((struct ether_addr *)eth_header->ether_shost));
        printf("   - dst mac: %s\n", ether_ntoa((struct ether_addr *)eth_header->ether_dhost));
        // IP 헤더
        printf("- IP Header\n");
        printf("   - src ip: %s\n", src_ip);
        printf("   - dst ip: %s\n", dst_ip);
        // TCP 헤더
        tcp_header = (struct tcphdr *)(packet + ETHER_HDR_LEN + (ip_header->ip_hl << 2));
        printf("- TCP Header\n");
        printf("   - src port: %d\n", ntohs(tcp_header->th_sport));
        printf("   - dst port: %d\n", ntohs(tcp_header->th_dport));
```

다음으로는 이더넷 헤더 의 프로토콜 유형이 IP인지 확인하고, IP 헤더의 프로토콜이 TCP인지 확인하도록 해주었습니다.

위 조건에 모두 해당된다면

- Ethernet Header: src mac / dst mac
- IP Header: src ip / dst ip
- TCP Header: src port / dst port

를 모두 출력하도록 해주었습니다.

```c
// Message 시작 위치와 길이 계산
int ip_total_length = ntohs(ip_header->ip_len);
int tcp_data_offset = ETHER_HDR_LEN + ip_header_length + (tcp_header->doff * 4);
int tcp_data_length = ip_total_length - (ip_header_length + (tcp_header->doff * 4));
// Message
if (tcp_data_length > 0) {
    printf("- Message (max 200 bytes binary):\n   ");
    int message;
    if (tcp_data_length > 200) {  // 200 bytes 까지만 출력
        message = 200;
    } else {
        message = tcp_data_length;
    }
    for (int i = 0; i < message; i++) {
        printf("%02x ", packet[tcp_data_offset + i]);
        if ((i + 1) % 16 == 0) printf("\n   ");
    }
    printf("\n");
}
```

그 후, IP 패킷 전체에서 이더넷, IP, TCP 헤더를 뺀 TCP 데이터를 출력하도록 해주었습니다. 출력하는 데이터는 최대 200바이트의 이진 데이터로 설정하였습니다.

```c
if (tcp_data_length > 0) {
                printf("- Message (max 200 bytes binary):\n   ");
                int message;
                if (tcp_data_length > 200) {  // 200 bytes 까지만 출력
                    message = 200;
                } else {
                    message = tcp_data_length;
                }
                for (int i = 0; i < message; i++) {
                    if (packet[tcp_data_offset + i] >= 32 && packet[tcp_data_offset + i] <= 126) {
                        printf("%c", packet[tcp_data_offset + i]);
                    } else {
                        printf(".");
                    }
                }
                printf("\n");
            }
```

위와 같이 작성하면 텍스트 데이터로 출력되는 것으로 보이나, 아래와 같이 출력이 되어 깔끔하게 이진 데이터로 출력하도록 해주었습니다.

![실행결과1](https://github.com/wxuycea/PACP-Programming/assets/129142444/dc1c850c-330d-420c-ac03-c6a24244665a)

### 실행 결과

![실행결과2](https://github.com/wxuycea/PACP-Programming/assets/129142444/6b613ce3-3a36-455e-a419-7fa2a06347f7)



- Ethernet Header: src mac / dst mac
- IP Header: src ip / dst ip
- TCP Header: src port / dst port
- Message 출력

위 조건들이 모두 출력되는 것을 확인할 수 있습니다.
