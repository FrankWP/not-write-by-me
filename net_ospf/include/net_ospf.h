#ifndef _NET_OSPF_H_
#define _NET_OSPF_H_

#include <sys/types.h>
#include <sys/wait.h>

#define LIBNET_ETH_H	(0x0e)    /**< Ethernet header:     14 bytes */
#define LIBNET_IPV4_H	(0x14)    /**< IPv4 header:         20 bytes */

#ifndef IPPROTO_OSPF
#define IPPROTO_OSPF	(89)  /* not everyone's got this */
#endif

/* program instance */
typedef struct _INSTANCE_T
{
	char host[SIZE_NAME];    /* host name Inside or OutSide */
	int index;               /* number of sub-process */
	pid_t pid;               /* process id */

	COM_CFG_T com_cfg;       /* common configure */
	RT_CFG_T rt_cfg;         /* router configure */

	void *data;              /* process private data */
}INSTANCE_T;

/* process private data */
typedef struct _PROCESS_T
{
	unsigned char *ip_packet;/* ip packet structure, perennial memory */
	pcap_t *device;          /* capture device */
	int dst_ip;              /* destination address */
	int lcl_ip;              /* local address */
	int src_ip;              /* source address */
	int net_ip;              /* source address net which filter */ 
	int raw_fd;              /* raw sockfd */
	char src_if[SIZE_NAME];  /* capture interface device */
	struct sockaddr_in raw_sin;
}PROCESS_T;

struct libnet_ospf_hdr
{
	u_int8_t ospf_v;          /* version */
#define OSPFVERSION         2
	u_int8_t ospf_type;       /* type */
#define  LIBNET_OSPF_UMD    0   /* UMd monitoring packet */
#define  LIBNET_OSPF_HELLO  1   /* HELLO packet */
#define  LIBNET_OSPF_DBD    2   /* dataBase description packet */
#define  LIBNET_OSPF_LSR    3   /* link state request packet */
#define  LIBNET_OSPF_LSU    4   /* link state Update Packet */
#define  LIBNET_OSPF_LSA    5   /* link state acknowledgement packet */
	u_int16_t   ospf_len;     /* length */
	struct in_addr ospf_rtr_id; /* source router ID */
	struct in_addr ospf_area_id;/* roam ID */
	u_int16_t ospf_sum;         /* checksum */
	u_int16_t ospf_auth_type;     /* authentication type */
#define LIBNET_OSPF_AUTH_NULL   0   /* null password */
#define LIBNET_OSPF_AUTH_SIMPLE 1   /* simple, plaintext, 8 int8_t password */
#define LIBNET_OSPF_AUTH_MD5    2   /* MD5 */
};

void net_master_signal_handler(int sig);
void net_master_process(INSTANCE_T *pinst);
void net_slave_signal_handler(int sig);
void net_slave_process(INSTANCE_T *pinst);
int  net_packet_ospf_parse(int net_ip, const U8 *packet, int packlen);
int  net_packet_ospf_forward(PROCESS_T *pdata, const U8 *packet, int packlen);
void net_packet_capture_callback(U8 *arg, const struct pcap_pkthdr *pkthdr, const U8 *packet);

#endif //_NET_OSPF_H_
