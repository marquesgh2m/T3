/*
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */
// Sources:
//[Get MAC address](http://www.microhowto.info/howto/get_the_mac_address_of_an_ethernet_interface_in_c_using_siocgifhwaddr.html)
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h> //strncpy
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h> // for ioctl commands Ex:SIOCGIFINDEX, SIOCGIFHWADDR
#include <net/if.h> // for ioctl commands, ifreq
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


// ARP Parser
#define ARP_CACHE       "/proc/net/arp"
#define STRING_LEN  1023
#define BUFFER_LEN  (STRING_LEN + 1)

#define xstr(s) str(s)
#define str(s) #s

/* Format for fscanf() to read the 1st, 4th, and 6th space-delimited fields */
#define ARP_LINE_FORMAT "%" xstr(STRING_LEN) "s %*s %*s " \
                        "%" xstr(STRING_LEN) "s %*s " \
                        "%" xstr(STRING_LEN) "s"

int getMacFromIp(char* dest_ip, char* dest_mac){
    //printf("DEST IP:%s\n",dest_ip);
    FILE *arpCache = fopen(ARP_CACHE, "r");

    /* Ignore/skip the first line, which contains the header */
    char header[BUFFER_LEN];
    fgets(header, sizeof(header), arpCache);

    // Read file line by line
    char ipAddr[BUFFER_LEN], hwAddr[BUFFER_LEN], device[BUFFER_LEN],macFromIp[BUFFER_LEN];
    int count = 0;

    while (3 == fscanf(arpCache, ARP_LINE_FORMAT, ipAddr, hwAddr, device)){
        //printf("%03d: Mac Address of [%s] on [%s] is \"%s\"\n",++count, ipAddr, device, hwAddr);
        if(strcmp(dest_ip,ipAddr)==0){
            strcpy(macFromIp,hwAddr);
            break;
        }
    }

    fclose(arpCache);

    //printf("DEST MAC:%s\n",dest_mac_str);

    if(strlen(macFromIp)!= 0){
        //printf("DEST MAC:%s\n",macFromIp);
        strcpy(dest_mac,macFromIp);
        return 1;
    }
    else return 0;
}



void split(char* source, uint8_t* splitted, char separator){
    long ret;
    char *ptr;
    for(int i=0;i<6;i++) splitted[i]=0; //clear var
    
    char buffer[BUFFER_LEN]; 
    int buffer_index = 0;
    int splitted_index = 0;
    int source_len = strlen(source);
    for(int i=0;i<=source_len;i++){
        if(source[i] != separator && source[i] != '\0'){
           buffer[buffer_index] = source[i]; 
           //printf("%c\n",buffer[buffer_index]);
           buffer_index++;
        }
        else{
            buffer[buffer_index] = '\0'; //close the string
            splitted[splitted_index] = strtoul(buffer, &ptr, 16);
            strcpy(buffer,""); //clean buffer
            splitted_index++;
            buffer_index = 0;
        }    
    }  

    //printf("Source:%s\n", source);
    //printf("SPLITTED MAC:%02X-%02X-%02X-%02X-%02X-%02X\n",splitted[0],splitted[1],splitted[2],splitted[3],splitted[4],splitted[5]);
}

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
    char dest_mac_str[BUFFER_LEN];
    uint8_t dest_mac[6];
    
    // Parse args
    if (argc > 1){
        strcpy(interfaceName, DEFAULT_IF);
        // look in ARP Table for the MAC related to IP
        getMacFromIp(argv[1],dest_mac_str);
        // split string and put each value in a uint vector position
        split(dest_mac_str,dest_mac,':');
        printf("DEST MAC:%02X-%02X-%02X-%02X-%02X-%02X\n",dest_mac[0],dest_mac[1],dest_mac[2],dest_mac[3],dest_mac[4],dest_mac[5]);
        //strcpy(interfaceName, argv[1]);
    }
    else {
        printf("Insert some IP\n");
        return 1;
        //strcpy(interfaceName, DEFAULT_IF);
    }

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
    eh->ether_dhost[0] = dest_mac[0];
    eh->ether_dhost[1] = dest_mac[1];
    eh->ether_dhost[2] = dest_mac[2];
    eh->ether_dhost[3] = dest_mac[3];
    eh->ether_dhost[4] = dest_mac[4];
    eh->ether_dhost[5] = dest_mac[5];
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
