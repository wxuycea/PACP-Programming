#include <arpa/inet.h>      // 인터넷 주소
#include <netinet/ether.h>  // 이더넷 프레임
#include <netinet/ip.h>     // IP 패킷
#include <netinet/tcp.h>    // TCP 세그먼트
#include <pcap.h>           // libpcap
#include <stdio.h>

int packet_count = 0;

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header;  // 이더넷 프레임 헤더 (<netinet/ether.h>)
    struct ip *ip_header;             // IP 프로토콜 헤더 (<netinet/ip.h>)
    struct tcphdr *tcp_header;        // TCP 세그먼트 헤더 (<netinet/tcp.h>)
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    int ip_header_length;

    eth_header = (struct ether_header *)packet;

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
        }
    }
}

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