/*
 Simple dns response sniffer .Open raw socket and start sniffing  udp packet and IP protocol 17.
 * If Proto is 17 then check for source port 53.
 * Check the no of answer received and parse it accordingly.
 */



#include<stdio.h> //scanf , printf
#include<string.h>    //strtok
#include<stdlib.h>    //realloc
#include<sys/socket.h>    //socket
#include<netinet/in.h> //sockaddr_in
#include<arpa/inet.h> //getsockname
#include<netdb.h> //hostent
#include<unistd.h>    //close
#include <netinet/udp.h>   //Provides declarations for udp header
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <net/if.h>//Provides ifreq
#include <linux/if_packet.h>

struct sniff_dns {
    u_short dns_id;
    u_short dns_flags;
    u_short dns_qdc;
    u_short dns_anc;
    u_short dns_nsc;
    u_short dns_arc;
};

void process_packet(unsigned char* buffer, int size);
int handle_dns(struct sniff_dns* dns, int size, char *sMAC);

int main(int argc, char **argv) {
    int saddr_size, data_size;
    struct sockaddr saddr;
    struct in_addr in;
    char* ifname = "br0";
    char* ifname1 = "apclii0";
    struct ifreq ifr;
    struct sockaddr_ll interfaceAddr;
    int ret;
    unsigned char buffer[9192];
RESTART:
    int sock_raw = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        //        LOG(Logger::ERROR, "startdns socket failed");
        sleep(15);
        goto RESTART;
    }

    memset(&interfaceAddr, 0, sizeof (interfaceAddr));
    memset(&ifr, 0, sizeof (ifr));

    memcpy(&ifr.ifr_name, ifname, IFNAMSIZ);

    if (ret = ioctl(sock_raw, SIOCGIFINDEX, &ifr) < 0) {
        printf("startdns ioctl failed\n");
        close(sock_raw);
        sleep(15);
        goto RESTART;
    }

    interfaceAddr.sll_ifindex = ifr.ifr_ifindex;
    interfaceAddr.sll_family = AF_PACKET;

    if (ret = bind(sock_raw, (struct sockaddr *) &interfaceAddr, sizeof (interfaceAddr)) < 0) {
        printf("startdns bind failed\n");
        close(sock_raw);
        sleep(15);
        goto RESTART;
    }
    saddr_size = sizeof saddr;
    while (1) {

        //Receive a packet
        data_size = recvfrom(sock_raw, buffer, 9192, 0, &saddr, (socklen_t*) & saddr_size);
        if (data_size < 0) {
            break;
        }
        //Now process the packet
        process_packet(buffer, data_size);
    }
    close(sock_raw);
    printf("Raw thread restarting\n");
    sleep(30); //wait someone is running init_system (internet.sh)
    goto RESTART;
    return NULL;


}

/**
 * Used to process packet received by raw socket.
 * It used to read all the arp request came or sent through router and create 
 * ARP entry with that.
 * @param buffer.Packet received by start_dns
 * @param size.Size of buffer.
 */
void process_packet(unsigned char* buffer, int size) {
    struct ether_header *eh;
    unsigned char *hash;
    //unsigned long ip;
    struct arphdr *arpheader;
    char cmd[300];
    eh = (struct ether_header*) buffer;

    if (size < (14 + 20 + 8)) {
        return;
    }
    char arpIp[50], arpIp2[50];
    char sAddr[50], rAddr[50];
    struct iphdr *iph = (struct iphdr*) (buffer + sizeof (struct ether_header));
    if (iph->protocol == 17) {
        unsigned short iphdrlen;
        iphdrlen = iph->ihl * 4;
        struct udphdr *udph = (struct udphdr*) (buffer + sizeof (struct ether_header) +iphdrlen);
        if (ntohs(udph->source) == 53) {
            char sMAC[50];
            printf("upd len->%d,calculated=%d\n", ntohs(udph->len), ntohs(iph->tot_len) - iphdrlen - sizeof (struct udphdr));
            sprintf(sMAC, "%02X:%02X:%02X:%02X:%02X:%02X", eh->ether_dhost[0], eh->ether_dhost[1], eh->ether_dhost[2], eh->ether_dhost[3], eh->ether_dhost[4], eh->ether_dhost[5]);
            handle_dns((struct sniff_dns*) ((unsigned char*) udph - 4), ntohs(iph->tot_len) - iphdrlen - sizeof (struct udphdr), sMAC);
        }
    }

}

int handle_dns(struct sniff_dns* dns, int size, char *sMAC) {
    unsigned char *payload, *payload1;
    int i;
    int listCount = 0;
    int len;
    int cur_ind;
    unsigned char domain_sub[1024];
    unsigned char *ptr_to_domain;
    unsigned long long t;
    int id = 0;
    int j = 0;
    char temp_domain[250], temp_domain1[250], temp_domain2[250];
    char *saveptr;
    char *foo, *bar = NULL;
    bool isIOT = 0;
    int maxCount = 0, LastCount = 0;
    payload = (unsigned char*) (dns) + sizeof (struct sniff_dns) + 4 + sizeof (struct udphdr);

    len = payload[0];
    cur_ind = 1;
    ptr_to_domain = domain_sub;
    //    printf("Current length=%d\n",len);

    while (len != 0) {
        if (j >= 256) {
            printf("Size of the URL is too big to handle ..\n");
            /* Size of the URL is too big to handle .. return */
            return 0;
        }
        for (i = cur_ind; i < cur_ind + len; i++) {
            ptr_to_domain[j++] = payload[i];
        }
        ptr_to_domain[j++] = '.';

        cur_ind = cur_ind + len + 1;
        len = payload[cur_ind - 1];
    }
    ptr_to_domain[j - 1] = 0;
    printf(" %s  =  ", ptr_to_domain);
    payload = (unsigned char*) (dns) + sizeof (struct sniff_dns);
    //int ip_size = size - 12;
    uint16_t answ = 0, dLen = 0;
    for (i = 0; i < size; i++) {
        if (i == 5) {
            printf("quest=%u,", ntohs(payload[i - 1] | payload[i] << 8));
        }
        if (i == 7) {
            printf("Reply=%u,", ntohs(payload[i - 1] | payload[i] << 8));
            // answ = payload[i];
            answ = ntohs(payload[i - 1] | payload[i] << 8);
        }
        if (answ != 0 && payload[i] == 0xc0) {//Start of reply header
            payload1 = payload + i;
            for (int j = 0; j < size; j++) {
                if (j == 3) {
//                    printf("Type=%u,", ntohs(payload1[j - 1] | payload1[j] << 8));
                } else if (j == 5) {
//                    printf("Class=%u,", ntohs(payload1[j - 1] | payload1[j] << 8));
                } else if (j == 11) {
//                    printf("Data Length==%u", ntohs(payload1[j - 1] | payload1[j] << 8));
                    dLen = ntohs(payload1[j - 1] | payload1[j] << 8);
                    if (dLen == 4) {
//                        printf("Its ip = ");

                        int ip;
                        char *ptr = (char*) &ip;
                        *ptr++ = payload1[j + 1];
                        *ptr++ = payload1[j + 2];
                        *ptr++ = payload1[j + 3];
                        *ptr++ = payload1[j + 4];
                        struct in_addr ip_addr;
                        ip_addr.s_addr = ip;
                        printf("IP address is %s\n", inet_ntoa(ip_addr));
                        break;
                    } else {
//                        printf("its Another Domain=");
//                        for (int k = 0; k < dLen; k++) {
//                            if (payload1[k] >= 32 && payload1[k] <= 128) {
//                                printf("%c", payload1[k]);
//                            } else {
//                                printf(".");
//                            }
//                        }
//                        printf("\n");
                        break;
                    }
                }
            }
            //            printf("Before i=%d,Now  i = %d\n", i, i + dLen + 12);
            i = i + dLen + 12 - 1; //12 is header length
        }
        //        if (payload[i] >= 32 && payload[i] <= 128) {
        //            printf("%02x ", (unsigned char) payload[i], (unsigned char) payload[i]); //if its a number or alphabet
        //        } else {
        //            printf("%02x ", (unsigned char) payload[i]);
        //        }
        //            printf("=%c %02x=   ", (unsigned char) payload[i],(unsigned char) payload[i]); //if its a number or alphabet

    }
    printf("\n");

    return 0;
}