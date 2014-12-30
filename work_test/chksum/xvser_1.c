#include<netinet/in.h>  
#include<sys/types.h>  
#include<sys/socket.h>  
#include<stdio.h>  
#include<stdlib.h>  
#include<string.h>  

unsigned short cal_chksum(unsigned short *addr,int len)
{       
	int nleft=len;
	int sum=0;
	unsigned short *w=addr;
	unsigned short answer=0;

	/*把ICMP报头二进制数据以2字节为单位累加起来*/
	while(nleft>1)
	{       
		sum+=*w++;
		nleft-=2;
	}
	/*若ICMP报头为奇数个字节，会剩下最后一字节。把最后一个字节视为一个2字节数据的高字节，
	 *                   这个2字节数据的低字节为0，继续累加*/
	if( nleft==1)
	{       
		*(unsigned char *)(&answer)=*(unsigned char *)w;
		sum+=answer;
	}
	sum=(sum>>16)+(sum&0xffff);
	sum+=(sum>>16);
	answer=~sum;
	return answer;
}

//part1 init socket
static void print_char(char ch)
{
	if(isprint(ch))
		fputc(ch, stdout);
	else
		fputc('.', stdout);
}

static void dis_interpret(const unsigned char *buf, int len)
{
	printf("\t");
	int idx = 0;
	while (idx < len)
		print_char(buf[idx++]);
	printf("\n");
}

#define t_disbuf(p, size) _t_disbuf((const unsigned char*)(p), (int)size)
void _t_disbuf(const unsigned char *buf, int len)
{
	int idx = 0;
	int len_tail = len % 16;
	const unsigned char *tail = buf + (len / 16) * 16;

	while(idx + 16 <= len)
	{
		printf("%04x  ", idx);
		printf("%02x %02x %02x %02x %02x %02x %02x %02x - %02x %02x %02x %02x %02x %02x %02x %02x ",
				buf[idx], buf[idx+1], buf[idx+2], buf[idx+3], buf[idx+4], buf[idx+5], buf[idx+6], buf[idx+7],
				buf[idx+8], buf[idx+9], buf[idx+10], buf[idx+11], buf[idx+12], buf[idx+13], buf[idx+14], buf[idx+15]);
		dis_interpret(buf + idx, 16);
		idx += 16;
	}

	if (idx < len - 1)
	{
		printf("%04x  ", idx);
		idx = 0;
		while (idx < 16)
		{
			if (idx == 8)
				printf("- ");
			if (idx < len_tail)
				printf("%02x ", tail[idx]);
			else
				printf("** ");

			++idx;
		}
		dis_interpret(tail, len_tail);
	}
}


 
int main(int argc, char **argv)  
{  
	unsigned short m = 2;
	unsigned short chk = 1;
	
	chk = cal_chksum(&m, 1);

	printf("%d\n", chk);
	
	m = m + chk;
	chk = cal_chksum(&m, 1);
	unsigned short n = 65535 + 1;
	printf("%d\n", n);

   return 0;  
}
  
