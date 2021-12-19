#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <errno.h>
#include <libnet.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdint.h>

#include "mac.h"
#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"

struct tcp_packet
{
    struct EthHdr eth_hdr;
    struct IpHdr ip_hdr;
    struct TcpHdr tcp_hdr;
    uint8_t data[1024];
};

char *pattern;
pcap_t *handle;

void usage()
{
    printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block ens33 \"test.gilgil.net\"\n");
}

Mac getmymac(void)
{
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;

    strncpy(ifr.ifr_name, "ens33", IFNAMSIZ - 1);
    ioctl(fd, SIOCGIFADDR, &ifr);

    close(fd);

    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1)
    { /* handle error*/
    };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1)
    { /* handle error */
    }

    struct ifreq *it = ifc.ifc_req;
    const struct ifreq *const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it)
    {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0)
        {
            if (!(ifr.ifr_flags & IFF_LOOPBACK))
            {
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0)
                {
                    success = 1;
                    break;
                }
            }
        }
        else
        { /* handle error */
        }
    }

    u_char temp[6] = {
        0,
    };
    if (success)
        memcpy(temp, ifr.ifr_hwaddr.sa_data, 6);

    return Mac(temp);
}

char *strnstr(const char *haystack, const char *needle, size_t len)
{
    int i;
    size_t needle_len;

    if (0 == (needle_len = strnlen(needle, len)))
        return (char *)haystack;

    for (i = 0; i <= (int)(len - needle_len); i++)
    {
        if ((haystack[0] == needle[0]) &&
            (0 == strncmp(haystack, needle, needle_len)))
            return (char *)haystack;

        haystack++;
    }
    return NULL;
}

void sendForwardPacket(const u_char *packet, int caplen, Mac mymac, bool isRST)
{
    u_char *new_packet = (u_char *)malloc(sizeof(tcp_packet) + 1);
    memcpy(new_packet, packet, caplen);
    struct tcp_packet *orgpkt = (tcp_packet *)packet;
    struct tcp_packet *newpkt = (tcp_packet *)new_packet;

    int datasize = orgpkt->ip_hdr.len() - orgpkt->ip_hdr.hl() * 4 - orgpkt->tcp_hdr.off() * 4;

    // Ethernet header
    newpkt->eth_hdr.smac_ = mymac;
    newpkt->eth_hdr.dmac_ = orgpkt->eth_hdr.dmac_;

    // IP header
    newpkt->ip_hdr.len_ = htons(sizeof(IpHdr) + sizeof(TcpHdr));
    newpkt->ip_hdr.ttl_ = orgpkt->ip_hdr.ttl_;
    newpkt->ip_hdr.sip_ = orgpkt->ip_hdr.sip_;
    newpkt->ip_hdr.dip_ = orgpkt->ip_hdr.dip_;

    // TCP header
    newpkt->tcp_hdr.sport_ = orgpkt->tcp_hdr.sport_;
    newpkt->tcp_hdr.dport_ = orgpkt->tcp_hdr.dport_;
    newpkt->tcp_hdr.seq_ = htonl(orgpkt->tcp_hdr.seq() + datasize);
    newpkt->tcp_hdr.ack_ = orgpkt->tcp_hdr.ack_;
    newpkt->tcp_hdr.off_rsvd_ = (sizeof(TcpHdr) >> 2) << 4;
    if (isRST)
        newpkt->tcp_hdr.flags_ = 0x04 | 0x10; //RST + ACK
    else
        newpkt->tcp_hdr.flags_ = 0x01 | 0x10; //FIN + ACK

    // Checksum
    newpkt->ip_hdr.sum_ = htons(IpHdr::calcChecksum(&(newpkt->ip_hdr)));
    newpkt->tcp_hdr.sum_ = htons(TcpHdr::calcChecksum(&(newpkt->ip_hdr), &(newpkt->tcp_hdr)));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(new_packet), sizeof(tcp_packet) + 1);
    if (res != 0)
    {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return;
    }
    free(new_packet);
    return;
}

void sendBackwardPacket(const u_char *packet, int caplen, Mac mymac, bool isHttp, bool isRST, char *FIN_message, bool isMessage)
{
    u_char *new_packet = (u_char *)malloc(sizeof(tcp_packet) + 1);
    memcpy(new_packet, packet, caplen);
    struct tcp_packet *orgpkt = (tcp_packet *)packet;
    struct tcp_packet *newpkt = (tcp_packet *)new_packet;

    int datasize = orgpkt->ip_hdr.len() - orgpkt->ip_hdr.hl() * 4 - orgpkt->tcp_hdr.off() * 4;

    // Ethernet header
    newpkt->eth_hdr.smac_ = mymac;
    newpkt->eth_hdr.dmac_ = orgpkt->eth_hdr.smac_;

    // IP header
    newpkt->ip_hdr.len_ = sizeof(IpHdr) + sizeof(TcpHdr);
    if (isHttp)
        newpkt->ip_hdr.len_ += strlen(FIN_message);
    newpkt->ip_hdr.len_ = htons(newpkt->ip_hdr.len_);
    newpkt->ip_hdr.ttl_ = 0x80;
    newpkt->ip_hdr.sip_ = orgpkt->ip_hdr.dip_;
    newpkt->ip_hdr.dip_ = orgpkt->ip_hdr.sip_;

    // TCP header
    newpkt->tcp_hdr.sport_ = orgpkt->tcp_hdr.dport_;
    newpkt->tcp_hdr.dport_ = orgpkt->tcp_hdr.sport_;
    newpkt->tcp_hdr.seq_ = orgpkt->tcp_hdr.ack_;
    newpkt->tcp_hdr.ack_ = htonl(orgpkt->tcp_hdr.seq() + datasize);
    newpkt->tcp_hdr.off_rsvd_ = (sizeof(TcpHdr) >> 2) << 4;
    if (isRST)
        newpkt->tcp_hdr.flags_ = 0x04 | 0x10;
    else
        newpkt->tcp_hdr.flags_ = 0x01 | 0x10;

    if (isMessage)
        memcpy(newpkt->data, FIN_message, strlen(FIN_message));

    // Checksum
    newpkt->ip_hdr.sum_ = htons(IpHdr::calcChecksum(&(newpkt->ip_hdr)));
    newpkt->tcp_hdr.sum_ = htons(TcpHdr::calcChecksum(&(newpkt->ip_hdr), &(newpkt->tcp_hdr)));

    int message_len = 0;
    if (isMessage)
        message_len = strlen(FIN_message);
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(new_packet), 14 + newpkt->ip_hdr.hl() * 4 + newpkt->tcp_hdr.off() * 4 + message_len);
    if (res != 0)
    {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return;
    }
    free(new_packet);
    return;
}

void block_http(const u_char *packet, int caplen)
{
    Mac mymac = getmymac();
    sendForwardPacket(packet, caplen, mymac, true);
    char fin_message[100] = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n";
    sendBackwardPacket(packet, caplen, mymac, true, false, fin_message, true);
}

void block_https(const u_char *packet, int caplen)
{
    Mac mymac = getmymac();
    sendForwardPacket(packet, caplen, mymac, true);
    sendBackwardPacket(packet, caplen, mymac, false, true, NULL, false);
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        usage();
        return -1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    pattern = argv[2];

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "open error on device%s(%s)\n", dev, errbuf);
        return -1;
    }

    while (true)
    {
        struct pcap_pkthdr *header;

        struct libnet_ethernet_hdr eth_hdr;
        struct libnet_ipv4_hdr ipv4_hdr;
        struct libnet_tcp_hdr tcp_hdr;

        const u_char *packet;
        u_char *p;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
            continue;
        if (res == -1 || res == -2)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        p = (u_char *)packet;
        memcpy(&eth_hdr, p, 14); // eth
        p += 14;
        memcpy(&ipv4_hdr, p, 20);  // ip
        if (ipv4_hdr.ip_p == 0x06) // if tcp
        {
            p += 20;
            memcpy(&tcp_hdr, p, 20); // tcp
            p += tcp_hdr.th_off * 4;
        }
        else
            continue;

        int datasize = ipv4_hdr.ip_len - ipv4_hdr.ip_hl * 4 - tcp_hdr.th_off * 4; //total len - ip header len - tcp header len

        // check pattern in packet
        if (strnstr((const char *)p, pattern, datasize))
        {
            // check whether http(s) or not
            if ((ntohs(tcp_hdr.th_sport) == 80) || (ntohs(tcp_hdr.th_dport) == 80))
            {
                printf("http block!\n");
                block_http(packet, header->caplen);
            }
            else if ((ntohs(tcp_hdr.th_sport) == 443) || (ntohs(tcp_hdr.th_dport) == 443))
            {
                {
                    printf("https block!\n");
                    block_https(packet, header->caplen);
                }
            }
        }
    }
    pcap_close(handle);
}