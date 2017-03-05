/*
 Simple dns response sniffer .Open raw socket and start sniffing  udp packet and IP protocol 17.
 * If Proto is 17 then check for source port 53.
 * Check the no of answer received and parse it accordingly.
 * /opt/buildroot-gcc463/usr/bin/mipsel-linux-g++ dnsResponse.cpp -o dRes -w -lpthread ;cp dRes /tftpboot/
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
#include <cstdio>
#include <cstdlib>
#include <map>
#include <list>
#include <string>
#include <pthread.h>
using namespace std;

struct clData { //Struct to hold each domain data usages.
    unsigned long long packets;
    unsigned long long size;
};
//std::list<char*> ipLists; //List of IP's 
std::map<string, std::list<string> > dnsIpList; // Map of each DNS to IP list.
std::map<string, std::map<string, struct clData> > macMap; //Map of MAC address pointing dns and packet count + size of total packets.

struct sniff_dns {
    u_short dns_id;
    u_short dns_flags;
    u_short dns_qdc;
    u_short dns_anc;
    u_short dns_nsc;
    u_short dns_arc;
};
pthread_t dns_thread;
void process_packet(unsigned char* buffer, int size);
int handle_dns(struct sniff_dns* dns, int size, char *sMAC);
void* start_dns(void *arg);

int main(int argc, char **argv) {
    if (pthread_create(&dns_thread, NULL, &start_dns, NULL) < 0) {
        printf("Unable to start dns thread");
    }
    while (1) {
        sleep(60); //To provide delay
        printf("=====================Map list size = %d.======================\n", dnsIpList.size());
        std::map<string, std::list<string> >::iterator itDns;
        for (itDns = dnsIpList.begin(); itDns != dnsIpList.end(); itDns++) {//Print Map
            std::list<string> ipLists = itDns->second;
            std::list<string>::iterator ipIt = ipLists.begin();
            printf("%s contains ", (itDns->first).c_str());
            for (; ipIt != ipLists.end(); ipIt++) {
                printf("%s,", (*ipIt).c_str());
            }
            printf("\n");
        }
        printf("=====================Data usage by each DNS is ============================\n");
        std::map<string, std::map<string, struct clData> >::iterator macMapIt = macMap.begin();
        for (; macMapIt != macMap.end(); macMapIt++) {
            printf("For MAC =%s\n", (macMapIt->first).c_str());
            std::map<string, struct clData>::iterator dnsDataIt = macMapIt->second.begin();
            printf("Dns list size =%d\n", macMapIt->second.size());
            for (; dnsDataIt != macMapIt->second.end(); dnsDataIt++) {
                printf("Dns = %s data packets=%llu and size = %llu\n", (dnsDataIt->first).c_str(), (dnsDataIt->second).packets, (dnsDataIt->second).size);
            }
        }
        printf("=====================Data usage Completed ============================\n");
    }
}

void* start_dns(void *arg) {
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
    char sIp[50], dIp[50];

    char sMAC[50], dMAC[50];
    //    printf("upd len->%d,calculated=%d\n", ntohs(udph->len), ntohs(iph->tot_len) - iphdrlen - sizeof (struct udphdr));
    sprintf(dMAC, "%02X:%02X:%02X:%02X:%02X:%02X", eh->ether_dhost[0], eh->ether_dhost[1], eh->ether_dhost[2], eh->ether_dhost[3], eh->ether_dhost[4], eh->ether_dhost[5]);
    sprintf(sMAC, "%02X:%02X:%02X:%02X:%02X:%02X", eh->ether_shost[0], eh->ether_shost[1], eh->ether_shost[2], eh->ether_shost[3], eh->ether_shost[4], eh->ether_shost[5]);

    //        printf("Destination mac = %s\n", dMAC);
    struct iphdr *iph = (struct iphdr*) (buffer + sizeof (struct ether_header));
    if (strcasecmp(dMAC, "c0:ee:fb:31:59:7a") == 0) { // If this Client packet comes.
        //        printf("Storing data\n");
        struct in_addr ip_addr;
        ip_addr.s_addr = iph->saddr;
        sprintf(dIp, "%s", inet_ntoa(ip_addr));
        std::map<string, std::list<string> >::iterator itDns;
        for (itDns = dnsIpList.begin(); itDns != dnsIpList.end(); itDns++) {//Start Dns map loop
            std::list<string> ipLists = itDns->second;
            std::list<string>::iterator ipIt = ipLists.begin();
            // printf("%s contains ", (itDns->first).c_str());
            for (; ipIt != ipLists.end(); ipIt++) {//Search every ip for all DNS.I know this sucks.
                if (strcasestr(dIp, (*ipIt).c_str())) {//Ip found in DNS list now Add size of this packed and increase count in MAC Map
                    std::map<string, std::map<string, struct clData> >::iterator mapMACIt = macMap.find((char*) dMAC);
                    //                    printf("Received packet for ip %s belongs to =%s\n", dIp, (itDns->first).c_str());
                    if (mapMACIt == macMap.end()) {//Not found in list lets add new entry
                        //                        printf("Mac not found,packet length=%d\n",ntohs(iph->tot_len));
                        std::map<string, struct clData> dnsData;
                        struct clData clD = {0, 0};
                        clD.packets++;
                        clD.size = ntohs(iph->tot_len);
                        dnsData[(itDns->first)] = clD;
                        macMap[dMAC] = dnsData;
                    } else {//MAC Found in the list.Now get DNS struct for this and update
                        std::map<string, struct clData> dnsData = mapMACIt->second;
                        std::map<string, struct clData>::iterator dnsDataIt = (dnsData.find(itDns->first));
                        if (dnsDataIt == (dnsData).end()) { // If DNS entry not found
                            //                            printf("Received first packet for this ip\n");
                            struct clData clD = {0, 0};
                            clD.packets = 1;
                            clD.size = ntohs(iph->tot_len);
                            dnsData[(itDns->first).c_str()] = clD;
                            //                            printf("Dns %s packet length=%d\n",(itDns->first).c_str(),ntohs(iph->tot_len));
                            macMap[dMAC] = dnsData;
                        } else { //DNS found  update packets
                            struct clData clD = dnsDataIt->second;
                            //                            printf("Data used before = %llu,%llu\n", clD.packets, clD.size);
                            clD.packets = clD.packets + 1;
                            clD.size = clD.size + ntohs(iph->tot_len);
                            dnsDataIt->second = clD;
                            macMap[dMAC] = dnsData;
                            //                            printf("Data used = %llu,%llu\n", clD.packets, clD.size);
                        }
                    }
                    break;
                }
            }
            if (ipIt == ipLists.end()) {//DNS entry not found map ip only then
                std::map<string, std::map<string, struct clData> >::iterator mapMACIt = macMap.find((char*) dMAC);
                //                    printf("Received packet for ip %s belongs to =%s\n", dIp, (itDns->first).c_str());
                if (mapMACIt == macMap.end()) {//Not found in list lets add new entry
                    //                        printf("Mac not found,packet length=%d\n",ntohs(iph->tot_len));
                    std::map<string, struct clData> dnsData;
                    struct clData clD = {0, 0};
                    clD.packets++;
                    clD.size = ntohs(iph->tot_len);
                    dnsData[dIp] = clD;
                    macMap[dMAC] = dnsData;
                } else {//MAC Found in the list.Now get DNS struct for this and update
                    std::map<string, struct clData> dnsData = mapMACIt->second;
                    std::map<string, struct clData>::iterator dnsDataIt = (dnsData.find(dIp));
                    if (dnsDataIt == (dnsData).end()) { // If DNS entry not found
                        //                            printf("Received first packet for this ip\n");
                        struct clData clD = {0, 0};
                        clD.packets = 1;
                        clD.size = ntohs(iph->tot_len);
                        dnsData[dIp] = clD;
                        //                            printf("Dns %s packet length=%d\n",(itDns->first).c_str(),ntohs(iph->tot_len));
                        macMap[dMAC] = dnsData;
                    } else { //DNS found  update packets
                        struct clData clD = dnsDataIt->second;
                        //                            printf("Data used before = %llu,%llu\n", clD.packets, clD.size);
                        clD.packets = clD.packets + 1;
                        clD.size = clD.size + ntohs(iph->tot_len);
                        dnsDataIt->second = clD;
                        macMap[dMAC] = dnsData;
                        //                            printf("Data used = %llu,%llu\n", clD.packets, clD.size);
                    }
                }
            }
            // printf("\n");
        }
    }

    if (iph->protocol == 17) {
        unsigned short iphdrlen;
        iphdrlen = iph->ihl * 4;
        struct udphdr *udph = (struct udphdr*) (buffer + sizeof (struct ether_header) +iphdrlen);
        if (ntohs(udph->source) == 53) {
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
    printf(" Got %s  =  ", ptr_to_domain);
    payload = (unsigned char*) (dns) + sizeof (struct sniff_dns);
    //int ip_size = size - 12;
    uint16_t answ = 0, dLen = 0;
    std::map<string, std::list<string> >::iterator dnsIt = dnsIpList.find((char*) ptr_to_domain);
    if (dnsIt == dnsIpList.end()) {
        std::list<string> ipLists;
        for (i = 0; i < size; i++) {
            if (i == 5) {
                printf("quest=%u,", ntohs(payload[i - 1] | payload[i] << 8));
            }
            if (i == 7) {
                printf("Reply=%u,IP = ", ntohs(payload[i - 1] | payload[i] << 8));
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
                            printf(" %s,", inet_ntoa(ip_addr));
                            ipLists.push_back(inet_ntoa(ip_addr));
                            break;
                        }
                    }
                }
                i = i + dLen + 12 - 1; //12 is header length
            }
        }
        dnsIpList[(char*) ptr_to_domain] = ipLists;
    }
    printf("\n");

    return 0;
}