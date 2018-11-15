/*
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h> // for ioctl commands Ex:SIOCGIFINDEX, SIOCGIFHWADDR
#include <net/if.h> // for ioctl commands
#include <netinet/ether.h>

#define MY_DEST_MAC0    0x00
#define MY_DEST_MAC1    0x00
#define MY_DEST_MAC2    0x00
#define MY_DEST_MAC3    0x00
#define MY_DEST_MAC4    0x00
#define MY_DEST_MAC5    0x00

#define ETHER_TYPE  0x0800

#define DEFAULT_IF  "vboxnet0"
#define BUF_SIZ     1518

int main(int argc, char *argv[]){
    int sockfd;
    struct ifreq if_idx;
    struct ifreq if_mac;
    int tx_len = 0;
    char sendbuf[BUF_SIZ];
    struct ether_header *eh = (struct ether_header *) sendbuf;
    struct iphdr *iph = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
    struct sockaddr_ll socket_address;
    char interfaceName[IFNAMSIZ];
    
    // Parse args
    if (argc > 1)
        strcpy(interfaceName, argv[1]);
    else
        strcpy(interfaceName, DEFAULT_IF);

    // Creates a Socket RAW
    //AF_PACKET for a packet socket
    //SOCK_RAW if you want to construct Ethernet header yourself
    //The htons() function makes sure that numbers are stored in memory in network byte order, which is with the most significant byte first. Converts the unsigned short integer hostshort from host byte order to network byte order. 
    // ETHER_TYPE is used for filtering inbound packets
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETHER_TYPE))) == -1) {
        perror("socket creation");
    }

    /* Get the index of the interface to send on */
    // eth0 by default
    // We need to know the index number of the network interface from which the frame is to be sent.
    // The interface index should have been returned in ifr.ifr_ifindex
    memset(&if_idx, 0, sizeof(struct ifreq)); // cleaning struct 
    strncpy(if_idx.ifr_name, interfaceName, IFNAMSIZ-1);
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
        perror("SIOCGIFINDEX");

    /* Get the MAC address of the interface to send on */
    // The hardware address of the interface should have been returned in ifr.ifr_hwaddr in the form of a struct sockaddr
    memset(&if_mac, 0, sizeof(struct ifreq));
    strncpy(if_mac.ifr_name, interfaceName, IFNAMSIZ-1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
        perror("SIOCGIFHWADDR");
    const uint8_t * source_mac=(uint8_t*)if_mac.ifr_hwaddr.sa_data;
    printf("SOURCE MAC:%02X:%02X:%02X:%02X:%02X:%02X\n",source_mac[0],source_mac[1],source_mac[2],source_mac[3],source_mac[4],source_mac[5]);

    // ======================================================================
    //Construct the Ethernet header
    // ======================================================================
    memset(sendbuf, 0, BUF_SIZ);
    // Ethernet header ( eh ) 
    eh->ether_shost[0] = source_mac[0];
    eh->ether_shost[1] = source_mac[1];
    eh->ether_shost[2] = source_mac[2];
    eh->ether_shost[3] = source_mac[3];
    eh->ether_shost[4] = source_mac[4];
    eh->ether_shost[5] = source_mac[5];
    eh->ether_dhost[0] = MY_DEST_MAC0;
    eh->ether_dhost[1] = MY_DEST_MAC1;
    eh->ether_dhost[2] = MY_DEST_MAC2;
    eh->ether_dhost[3] = MY_DEST_MAC3;
    eh->ether_dhost[4] = MY_DEST_MAC4;
    eh->ether_dhost[5] = MY_DEST_MAC5;
    /* Ethertype field */
    eh->ether_type = htons(ETH_P_IP);
    tx_len += sizeof(struct ether_header);

    /* Packet data */
    sendbuf[tx_len++] = 0xde;
    sendbuf[tx_len++] = 0xad;
    sendbuf[tx_len++] = 0xbe;
    sendbuf[tx_len++] = 0xef;

    /* Index of the network device */
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    /* Address length*/
    socket_address.sll_halen = ETH_ALEN;
    /* Destination MAC */
    socket_address.sll_addr[0] = MY_DEST_MAC0;
    socket_address.sll_addr[1] = MY_DEST_MAC1;
    socket_address.sll_addr[2] = MY_DEST_MAC2;
    socket_address.sll_addr[3] = MY_DEST_MAC3;
    socket_address.sll_addr[4] = MY_DEST_MAC4;
    socket_address.sll_addr[5] = MY_DEST_MAC5;

    /* Send packet */
    if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
        printf("Send failed\n");

    return 0;
}
