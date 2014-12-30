#include <sys/types.h>       // socket
#include <sys/socket.h>      // socket
#include <sys/ioctl.h>       // ioctl
#include <net/if.h>          // ifreq 
#include <string.h>          // strcpy
#include <stdio.h>           // printf
#include <linux/if_packet.h> // sockaddr_ll

#define BOOL   unsigned char
#define U8     unsigned char
#define U16    unsigned short 
#define TRUE   1
#define FALSE  0

static int fd;
static unsigned char if_mac[6];
static int if_index;

U8  gBuf[2000] = {0};
U8  gTxBuf[2000];
U16 gLen=0;

BOOL InitEtherNetIf(void)
{
	struct ifreq req;
	if ( (fd = socket(PF_PACKET, SOCK_RAW, htons(0x0003) ) ) < 0 )
	{                         
		printf( "failed to create raw socket!\n" );
		return FALSE;
	}

	strcpy( req.ifr_name, "eth0" );
	if ( ioctl( fd, SIOCGIFFLAGS, &req ) < 0 )
	{
		printf( "failed to do ioctl!" );
		return FALSE;
	}

	req.ifr_flags |= IFF_PROMISC;

	if ( ioctl( fd, SIOCSIFFLAGS, &req ) < 0 )
	{
		printf( "failed to set eth0 into promisc mode!" );
		return FALSE;
	}

	if ( ioctl( fd, SIOCGIFHWADDR, &req ) < 0 )
	{
		printf( "failed to get IF hw address!" );
		return FALSE;
	}

	memcpy( if_mac, req.ifr_hwaddr.sa_data, sizeof(if_mac) );

	if ( ioctl( fd, SIOCGIFINDEX, &req ) < 0 )
	{
		printf( "failed to get IF hw address!" );
		return FALSE;
	}

	if_index = req.ifr_ifindex;
	return TRUE;
}

BOOL GetPacket(U8 *buf, U16 *len) 
{
	int length = 0;

	length = recvfrom( fd, buf, 2000, 0, NULL, NULL );
	if ( length < 0 )
	{
		return 0;
	} 
	else
	{
		*len = length;
		return 1;
	}
}

BOOL SendPacket(U8 *buf, U16 len)
{
	int errno;
	struct sockaddr_ll link;
	link.sll_ifindex = if_index;
	memcpy( link.sll_addr, buf, link.sll_halen );

	errno = sendto( fd, buf, len, 0, (struct sockaddr *)&link, sizeof(link) );
	if (errno < 0)
	{
		printf("ERRNO:%d\n", errno);
		printf( "failed to send to RAW socket!\r\n" );   
		return 0;
	}
	return 1;
}

BOOL GetMacAddress(U8 *mac)
{
	memcpy(mac, if_mac, sizeof(if_mac));
	return TRUE;
}

void DispalyBuf(U8 *buf,U16 size)
{
	int i;
	for(i=0;i<size;i++)
	{      
		if((0==i%16)&&(i>0)) printf("\n");
		printf("%02x ",buf[i]); 
	}
	printf("\n");
}

int main(void)
{
	BOOL ret;   
	for(ret =0;ret<64;ret++) gTxBuf[ret]=ret;

	if(InitEtherNetIf())
	{
		printf("send:\n");
		DispalyBuf(gTxBuf,64);
		SendPacket(gTxBuf,64);
		while(1)
		{
			if(GetPacket(gBuf,&gLen))
			{
				printf("start to recive-----------\n");
				DispalyBuf(gBuf,gLen);
				printf("end to recive-------------\n");
				sleep(1);
			}
		} 
	}
}
