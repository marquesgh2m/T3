#define ETH_LEN	1518
#define ETHER_TYPE	0x0800

struct eth_hdr {
	uint8_t dst_addr[6];
	uint8_t src_addr[6];
	uint16_t eth_type;
};

struct ip_hdr {
	uint8_t ver;			/* version, header length */
	uint8_t tos;			/* type of service */
	int16_t len;			/* total length */
	uint16_t id;			/* identification */
	int16_t off;			/* fragment offset field */
	uint8_t ttl;			/* time to live */
	uint8_t proto;			/* protocol */
	uint16_t sum;			/* checksum */
	uint8_t src[4];			/* source address */
	uint8_t dst[4];			/* destination address */
};

struct icmp_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seqNum;
};

struct icmp_packet{
    struct ip_hdr iphdr;
    struct icmp_hdr icmphdr;
};

union packet_u {
	struct ip_hdr ip;
	struct icmp_packet icmp;
};

struct eth_frame_s {
	struct eth_hdr ethernet;
	union packet_u payload;
};

union eth_buffer {
	struct eth_frame_s cooked_data;
	uint8_t raw_data[ETH_LEN];
};
