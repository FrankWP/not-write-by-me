#include <stdlib.h>
#include <stdio.h>

#include "common.h"
#include "libnet.h"
#include "config.h"

int main(int argc, char* argv[])
{
	int cnt = 0;
	int network,			/* network interface */
		packet_size,		/* packet size */
		c;					/* misc */
	int ret = -1;			/* result */

	/* Address */
	u_long src_ip = 0,
		   nhb_ip = 0,
		   dst_ip = 0;

	/* Packet of libnet context */
	libnet_t *packet = NULL;

	char errbuf[LIBNET_ERRBUF_SIZE] = {0};

	/* Authentication */
	u_char auth[8] = {0,0,0,0,0,0,0,0};

	/* Initialize the library.  Root priviledges are required. */
	packet = libnet_init(
			LIBNET_RAW4,	/* injection type */
			NULL,			/* network interface */
			errbuf);

	if (!packet) {
		LOGW("libnet_init() failed: %s", errbuf);
		
		goto _E1;
	}
	
	/* Input */
	if (argc != 4) {
		printf("%s [srcip] [dstip] [neighbor]\n", argv[0]);
		goto _E2;
	}
	else {
		src_ip = libnet_name2addr4(packet, argv[1], LIBNET_RESOLVE);
		if (!src_ip) {
			LOGW("Bad source IP address: %s\n", argv[1]);
			goto _E2;
		}

		dst_ip = libnet_name2addr4(packet, argv[2], LIBNET_RESOLVE);
		if (!dst_ip) {
			LOGW("Bad destination IP address: %s\n", argv[2]);
			goto _E2;
		}

		nhb_ip = libnet_name2addr4(packet, argv[3], LIBNET_RESOLVE);
		if (!nhb_ip) {
			LOGW("Bad neighbor IP address: %s\n", argv[3]);
			goto _E2;
		}
	}

	/* Construct the Hello Data */
	ret = libnet_build_ospfv2_hello(
			0xffffffff,				/* netmask */
			2,						/* interval */
			0x00,					/* options */
			0x00,					/* priority */
			30,						/* dead int */
			src_ip,					/* router */
			src_ip,					/* router */
			nhb_ip,					/* neighbor */
			NULL,					/* payload */
			0,						/* payload size */
			packet,					/* libnet handle */
			0);						/* libnet id */

	if (FAILURE == ret) {
		LOGW("Can't build OSPF HELLO header: %s\n", packet->err_buf);
		goto _E2;
	}	
	
	/* Construct the Authentication Data */
	ret = libnet_build_data(
			auth,					/* auth data */
			LIBNET_OSPF_AUTH_H,		/* payload size */
			packet,					/* libnet handle */
			0);						/* libnet id */

	if (FAILURE == ret) {
		LOGW("Can't build OSPF auth header: %s\n", packet->err_buf);
		goto _E2;
	}

	/* Construct the OSPF header */
	ret = libnet_build_ospfv2(
			LIBNET_OSPF_HELLO_H + 
			LIBNET_OSPF_AUTH_H,		/* OSPF packet length */ 		
			LIBNET_OSPF_HELLO,		/* OSPF packet type */
			htonl(0x02010101),		/* router id */
			htonl(0x00000000),		/* area id */
			0,						/* checksum */
			LIBNET_OSPF_AUTH_NULL,	/* auth type */
			NULL,					/* payload */
			0,						/* payload size */
			packet,					/* libnet handle */
			0);						/* libnet id */

	if (FAILURE == ret) {
		LOGW("Can't build OSPF header: %s\n", packet->err_buf);
		goto _E2;
	}

	/* Construct the IPv4 header */
	ret = libnet_build_ipv4(
			LIBNET_IPV4_H + 
			LIBNET_OSPF_H +
			LIBNET_OSPF_HELLO_H + 
			LIBNET_OSPF_AUTH_H,		/* packet total legnth */
			0,						/* TOS */
			101,					/* IP ID */
			IP_DF,					/* IP frag */
			64,						/* TTL */
			IPPROTO_OSPF,			/* protocol */
			0,						/* checksum */
			src_ip,					/* source IP */
			dst_ip,					/* destination IP */
			NULL,					/* payload */
			0,						/* payload size */
			packet,					/* libnet handle */
			0);						/* libnet id */

	if (FAILURE == ret) {
		LOGW("Can't build IP header: %s\n", packet->err_buf);
		goto _E2;
	}

	while (1) {
		
		/* Write packet to the wire. */
		ret = libnet_write(packet);
		if (FAILURE == ret) {
			LOGW("Write err: %s\n", packet->err_buf);
			goto _E2;
		}

		LOGD("Send OSPF HELLO packet#%d\n", cnt);
		cnt++;

		sleep(1);
	}
	
	libnet_destroy(packet);
	goto _S0;

_E2:
	libnet_destroy(packet);
_E1:
	return -1;
_S0:
	LOGD("Send OSPF HELLO packet success\n");
	return 0;
}
