#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#define BUFFER_MAX 1500

#define get_u32(X,O)  (*(__u32 *)(X + O))
#define get_u16(X,O)  (*(__u16 *)(X + O))
#define get_u8(X,O)  (*(__u8 *)(X + O))

int main(int argc, char *argv[])
{
	int sock, n_read, proto;        
	char buffer[BUFFER_MAX];
	char ip[1024]={'\0'};
	char  *ethhead, *iphead, *tcphead, 
		  *udphead, *icmphead, *p;

	if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0)
	{
		fprintf(stdout, "create socket error\n");
		exit(-1);
	}

	while(1) 
	{
		n_read = recvfrom(sock, buffer, 2048, 0, NULL, NULL);
		if(n_read < 42) 
		{
			fprintf(stdout, "Incomplete header, packet corrupt\n");
			continue;
		}

		printf("recive byted:%d\n");

		ethhead = buffer;
		p = ethhead;
		int n = 0XFF;

		iphead=buffer+26;
		unsigned long source_ip=get_u32(iphead,0);

		if(inet_addr("10.0.0.123")==source_ip)
		{
			if(get_u8(buffer+23,0)==0x06)
			{
				printf("tcp package\n");		
			}
		}
	}
}
