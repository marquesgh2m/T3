/**
 *  tunnel.c
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <pwd.h>
#include <pthread.h>
#include <unistd.h>
#include "tunnel.h"
#include "raw.h"

#define MTU 1472
#define DEFAULT_ROUTE   "0.0.0.0"

#define IP_SERVER0 192
#define IP_SERVER1 168
#define IP_SERVER2 0
#define IP_SERVER3 1

#define IP_CLIENT0 192
#define IP_CLIENT1 168
#define IP_CLIENT2 0
#define IP_CLIENT3 103

#define IP_REDIRECT0 192
#define IP_REDIRECT1 168
#define IP_REDIRECT2 0
#define IP_REDIRECT3 101

// Protocol numbers
#define ICMP 1
#define TCP 6

/**
 * Function to allocate a tunnel
 */
int tun_alloc(char *dev, int flags)
{
	struct ifreq ifr;
	int tun_fd, err;
	char *clonedev = "/dev/net/tun";
	printf("[DEBUG] Allocating tunnel\n");

	tun_fd = open(clonedev, O_RDWR);

	if(tun_fd == -1) {
		perror("Unable to open clone device\n");
		exit(EXIT_FAILURE);
	}

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = flags;

	if (*dev) {
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}

	if ((err=ioctl(tun_fd, TUNSETIFF, (void *)&ifr)) < 0) {
		close(tun_fd);
		fprintf(stderr, "Error returned by ioctl(): %s\n", strerror(err));
		perror("Error in tun_alloc()\n");
		exit(EXIT_FAILURE);
	}

	printf("[DEBUG] Created tunnel %s\n", dev);

	return tun_fd;
}

/**
 * Function to read from a tunnel
 */
int tun_read(int tun_fd, char *buffer, int length)
{
	int bytes_read;
	bytes_read = read(tun_fd, buffer, length);

	if (bytes_read == -1) {
		perror("Unable to read from tunnel\n");
		exit(EXIT_FAILURE);
	} else {
		return bytes_read;
	}
}

/**
 * Function to write to a tunnel
 */
int tun_write(int tun_fd, char *buffer, int length){
	printf("Tun_write size:%d\n",length);
	int bytes_written;
	bytes_written = write(tun_fd, buffer, length);

	if (bytes_written == -1) {
		perror("Unable to write to tunnel\n");
		exit(EXIT_FAILURE);
	} else {
		return bytes_written;
	}
}

/**
 * Function to configure the network
 */
void configure_network(int server)
{
	int pid, status;
	char path[100];
	char *const args[] = {path, NULL};

	if (server) {
		if (sizeof(SERVER_SCRIPT) > sizeof(path)){
			perror("Server script path is too long\n");
			exit(EXIT_FAILURE);
		}
		strncpy(path, SERVER_SCRIPT, strlen(SERVER_SCRIPT) + 1);
	} else {
		if (sizeof(CLIENT_SCRIPT) > sizeof(path)){
			perror("Client script path is too long\n");
			exit(EXIT_FAILURE);
		}
		strncpy(path, CLIENT_SCRIPT, strlen(CLIENT_SCRIPT) + 1);
	}

	pid = fork();

	if (pid == -1) {
		perror("Unable to fork\n");
		exit(EXIT_FAILURE);
	}

	if (pid==0) {
		// Child process, run the script
		exit(execv(path, args));
	} else {
		// Parent process
		waitpid(pid, &status, 0);
		if (WEXITSTATUS(status) == 0) {
			// Script executed correctly
			printf("[DEBUG] Script ran successfully\n");
		} else {
		// Some error
		printf("[DEBUG] Error in running script\n");
		}
	}
}

void print_hexdump(char *str, int len){
	int i;
	for (i = 0; i < len; i ++) {
		if (i % 16 == 0) printf("\n    ");
		printf("%02x ", (unsigned char)str[i]);
	}
	printf("\n");
}

void print_asciidump(char *str, int len){
	int i;
	for (i = 0; i < len; i ++) {
		if (i % 16 == 0) printf("\n    ");
		printf("%c ", (unsigned char)str[i]);
	}
	printf("\n");
}

void print_decdump(char *str, int len){
    int i;
    for (i = 0; i < len; i ++) {
        if (i % 16 == 0) printf("\n    ");
        printf("%02d ", (unsigned char)str[i]);
    }
    printf("\n");
}

uint32_t ipchksum(uint8_t *packet)
{
	uint32_t sum=0;
	uint16_t i;

	for(i = 0; i < 20; i += 2)
		sum += ((uint32_t)packet[i] << 8) | (uint32_t)packet[i + 1];
	while (sum & 0xffff0000)
		sum = (sum & 0xffff) + (sum >> 16);
	return sum;
}

uint16_t icmpchksum(uint16_t *addr, int len)
{
  //printf("chksum_len:%d\n", len);
  int nleft = len;
  uint32_t sum = 0;
  uint16_t *w = addr;
  uint16_t answer = 0;

  // Adding 16 bits sequentially in sum
  while (nleft > 1) {
    sum += *w;
    nleft -= 2;
    w++;
  }

  // If an odd byte is left
  if (nleft == 1) {
    *(uint8_t *) (&answer) = *(uint8_t *) w;
    sum += answer;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;

  return answer;
}

/**
 * Function to run the tunnel
 */
void run_tunnel(char *dest, int server, int argc, char *argv[]){
	char this_mac[6];
	char bcast_mac[6] =	{0x08, 0x00, 0x27, 0x67, 0x42, 0xa8};
	char dst_mac[6] =	{0x08, 0x00, 0x27, 0x67, 0x42, 0xa8};
	char src_mac[6] =	{0x0a, 0x00, 0x27, 0x00, 0x00, 0x00};

	char payload[1500];
	union eth_buffer buffer_u;

	struct ifreq if_idx, if_mac, ifopts;
	char ifName[IFNAMSIZ];
	struct sockaddr_ll socket_address;
	int sock_fd, tun_fd, size;
    int j = 0;

	fd_set fs;

	tun_fd = tun_alloc("tun0", IFF_TUN | IFF_NO_PI);

	printf("[DEBUG] Starting tunnel - Dest: %s, Server: %d\n", dest, server);
	printf("[DEBUG] Opening socket\n");

	/* Get interface name */
	if (argc > 3)
		strcpy(ifName, argv[3]);
	else{
		perror("Error configuring interface\n");
		exit(1);
	}

	/* Open RAW socket */
	if ((sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
		perror("socket");

	/* Set interface to promiscuous mode */
	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
	ioctl(sock_fd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sock_fd, SIOCSIFFLAGS, &ifopts);

	/* Get the index of the interface */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sock_fd, SIOCGIFINDEX, &if_idx) < 0)
		perror("SIOCGIFINDEX");
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	socket_address.sll_halen = ETH_ALEN;

	/* Get the MAC address of the interface */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sock_fd, SIOCGIFHWADDR, &if_mac) < 0)
		perror("SIOCGIFHWADDR");
	memcpy(this_mac, if_mac.ifr_hwaddr.sa_data, 6);

	configure_network(server);

	while (1) {
		FD_ZERO(&fs);
		FD_SET(tun_fd, &fs);
		FD_SET(sock_fd, &fs);

		select(tun_fd > sock_fd ? tun_fd+1 : sock_fd+1, &fs, NULL, NULL, NULL);

		if (FD_ISSET(tun_fd, &fs)&&
            buffer_u.cooked_data.payload.ip.proto == TCP) {
			printf("\e[0;32m"); //GREEN
            printf("[DEBUG] Read tun device {\n");

			memset(&payload, 0, sizeof(payload));
			size  = tun_read(tun_fd, payload, MTU);
			if(size  == -1) {
				perror("Error while reading from tun device\n");
				exit(EXIT_FAILURE);
			}
			
			print_hexdump(payload, size);
            print_asciidump(payload, size);
			//print_decdump(payload, size);

			printf("}\n\n");
            printf("\e[0m"); //No Color

			/* Fill the Ethernet frame header */
			memcpy(buffer_u.cooked_data.ethernet.dst_addr, bcast_mac, 6);
			memcpy(buffer_u.cooked_data.ethernet.src_addr, src_mac, 6);
			buffer_u.cooked_data.ethernet.eth_type = htons(ETH_P_IP);

			// int posicao = sizeof(struct eth_hdr)+sizeof(struct ip_hdr)+sizeof(struct icmp_hdr);
			// char mensagem[sizeof(tcp_b.mensagem)];
			// memcpy(mensagem, tcp_b.mensagem, sizeof(tcp_b.mensagem));

			/* Fill IP header data. Fill all fields and a zeroed CRC field, then update the CRC! */
			buffer_u.cooked_data.payload.ip.ver = 0x45;
			buffer_u.cooked_data.payload.ip.tos = 0x00;
			buffer_u.cooked_data.payload.ip.len = htons(size + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr));
			buffer_u.cooked_data.payload.ip.id = htons(0x00);
			buffer_u.cooked_data.payload.ip.off = htons(0x00);
			buffer_u.cooked_data.payload.ip.ttl = 40;
			buffer_u.cooked_data.payload.ip.proto = 0x01; //ICMP
			buffer_u.cooked_data.payload.ip.sum = htons(0x0000);

			if (server) {
				buffer_u.cooked_data.payload.ip.src[0] = IP_SERVER0;
				buffer_u.cooked_data.payload.ip.src[1] = IP_SERVER1;
				buffer_u.cooked_data.payload.ip.src[2] = IP_SERVER2;
				buffer_u.cooked_data.payload.ip.src[3] = IP_SERVER3;
				buffer_u.cooked_data.payload.ip.dst[0] = IP_CLIENT0;//IP_REDIRECT0;
				buffer_u.cooked_data.payload.ip.dst[1] = IP_CLIENT1;//IP_REDIRECT1;
				buffer_u.cooked_data.payload.ip.dst[2] = IP_CLIENT2;//IP_REDIRECT2;
				buffer_u.cooked_data.payload.ip.dst[3] = IP_CLIENT3;//IP_REDIRECT3;
			} else {
				buffer_u.cooked_data.payload.ip.src[0] = IP_SERVER0;
				buffer_u.cooked_data.payload.ip.src[1] = IP_SERVER1;
				buffer_u.cooked_data.payload.ip.src[2] = IP_SERVER2;
				buffer_u.cooked_data.payload.ip.src[3] = IP_SERVER3;
				buffer_u.cooked_data.payload.ip.dst[0] = IP_CLIENT0;
				buffer_u.cooked_data.payload.ip.dst[1] = IP_CLIENT1;
				buffer_u.cooked_data.payload.ip.dst[2] = IP_CLIENT2;
				buffer_u.cooked_data.payload.ip.dst[3] = IP_CLIENT3;
                //ICMP
    			buffer_u.cooked_data.payload.icmp.icmphdr.type = 8;
    		    buffer_u.cooked_data.payload.icmp.icmphdr.code = 0;
    		    buffer_u.cooked_data.payload.icmp.icmphdr.checksum = 0; // clean vector 
    		    buffer_u.cooked_data.payload.icmp.icmphdr.id = htons(0xF0CA);
    		    buffer_u.cooked_data.payload.icmp.icmphdr.seqNum = htons(0x0001); 
            
                /* Fill the payload */
                memcpy(buffer_u.raw_data + sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), payload, size);
                memcpy(socket_address.sll_addr, dst_mac, 6);

                // Calc Checksums
                buffer_u.cooked_data.payload.ip.sum = htons((~ipchksum((uint8_t *)&buffer_u.cooked_data.payload.ip) & 0xffff));
                buffer_u.cooked_data.payload.icmp.icmphdr.checksum =  icmpchksum((uint16_t *) &buffer_u.cooked_data.payload.icmp.icmphdr, sizeof(struct icmp_hdr) + size);
                //printf("checksum:%02x\n", buffer_u.cooked_data.payload.icmp.icmphdr.checksum);
                
                // Send 
                if (sendto(sock_fd, buffer_u.raw_data, size + sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
                    printf("Send failed\n");
                printf("[DEBUG] Sent packet\n");
            }

   
		}
        printf("\e[0;31m"); //red



		// READING (IN PROMISCUOUS MODE)
		//FD_ISSET(fd, &fdset): Returns a non-zero value if the bit for the file descriptor fd is set in the file descriptor set pointed to by fdset, and 0 otherwise.
		if (FD_ISSET(sock_fd, &fs)) {
			size = recvfrom(sock_fd, buffer_u.raw_data, ETH_LEN, 0, NULL, NULL);
			if(buffer_u.cooked_data.payload.ip.proto == TCP){
                printf("    ip.src:    ");
                for(j = 0;j<4;j++){
                    printf("%02d",buffer_u.cooked_data.payload.ip.src[j]);
                    if(j<4-1)printf(":");
                }
                printf("\n    ip.dst:    ");
                for(j = 0;j<4;j++){
                    printf("%02d",buffer_u.cooked_data.payload.ip.dst[j]);
                    if(j<4-1)printf(":");
                }


                printf("\n    ip.proto:  ");
                printf("%u",buffer_u.cooked_data.payload.ip.proto);
                switch(buffer_u.cooked_data.payload.ip.proto){
                    case 1:
                        printf("(ICMP)");
                        break;
                    case 6:
                        printf("(TCP)");
                        break;
                    case 17:
                        printf("(UDP)");
                        break;
                }

                printf("\n    size:%d",size);

                print_hexdump((char*)buffer_u.raw_data, size);
                print_asciidump((char*)buffer_u.raw_data, size);

                size = size - sizeof(struct eth_hdr); //redimenciona o tamanho para nao pegar lixo
                memset(&payload, 0, sizeof(payload));
                memcpy(payload, buffer_u.raw_data + sizeof(struct eth_hdr), size);

                print_hexdump(payload, size);
                print_asciidump(payload, size);

                tun_write(tun_fd, payload, size);
                /*if (buffer_u.cooked_data.ethernet.eth_type == ntohs(ETH_P_IP) &&
                        buffer_u.cooked_data.payload.ip.proto == 1){ //ICMP
    				printf("IDENTIFIED ip.dst:    ");
                        for(j = 0;j<4;j++){
                            printf("%02d",buffer_u.cooked_data.payload.ip.dst[j]);
                            if(j<4-1)printf(":");
                        }
                    if (server) {
    					if (buffer_u.cooked_data.payload.ip.dst[0] == IP_CLIENT0 && buffer_u.cooked_data.payload.ip.dst[1] == IP_CLIENT1 &&
    						buffer_u.cooked_data.payload.ip.dst[2] == IP_CLIENT2 && buffer_u.cooked_data.payload.ip.dst[3] == IP_CLIENT3){
    						memcpy(payload, buffer_u.raw_data + sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), size);
    						print_hexdump(payload, size);
    						print_asciidump(payload, size);
    						tun_write(tun_fd, payload, size);
    						printf("[DEBUG][ETH_P_IP] Write tun device\n");
    					}
    				} else {
    					printf("    %02d:%02d:%02d:%02d",IP_CLIENT0,IP_CLIENT1,IP_CLIENT2,IP_CLIENT3);
    					printf("\n");
    					if (buffer_u.cooked_data.payload.ip.dst[0] == IP_CLIENT0 && buffer_u.cooked_data.payload.ip.dst[1] == IP_CLIENT1 &&
    						buffer_u.cooked_data.payload.ip.dst[2] == IP_CLIENT2 && buffer_u.cooked_data.payload.ip.dst[3] == IP_CLIENT3){
    						memcpy(payload, buffer_u.raw_data + sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), size);
    						print_hexdump(payload, size);
    						print_asciidump(payload, size);
    						tun_write(tun_fd, payload, size);
    						printf("[DEBUG][ETH_P_IP] Write tun device\n");
    					}
    				}
    			}*/
            }
		}
        printf("\e[0m"); //No Color
	}
}

