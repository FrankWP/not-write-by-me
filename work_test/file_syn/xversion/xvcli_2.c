#include<netinet/in.h>                         // for sockaddr_in  
#include<sys/types.h>                          // for socket  
#include<sys/socket.h>                         // for socket  
#include<stdio.h>                              // for printf  
#include<stdlib.h>                             // for exit  
#include<string.h>                             // for bzero  
#include <unistd.h>
#include <stdarg.h>
#include <getopt.h>
#include <errno.h>
#include <syslog.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>
#include <dlfcn.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
  
#define HELLO_WORLD_SERVER_PORT       5000
#define BUFFER_SIZE                   1024  
#define FILE_NAME_MAX_SIZE            512  

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
void _t_disbuf(const unsigned char *buf, int len);
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



//part 1
void par_args(int argc, char **argv)
{
	if (argc < 2)  
    {  
        printf("Usage: ./%s TransFileNames\n", argv[0]);  
        exit(1);  
    }  
}

void pars_filename(int argc, char **argv)
{
	int i;
	for (i=1; i<argc; i++)
	{
		if (read_file(argv[i]) < 0)
		{
			//printf("readfile %s failed!\n", argv[i]);
			continue;
		}
	}		
}

/*校验和算法*/
unsigned short cal_chksum(unsigned short *addr,int len)
{       
	if ((addr == NULL) || (len == 0))
		return 0;

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

//icmp->icmp_cksum=cal_chksum( (unsigned short *)icmp,packsize); /*校验算法*/

int read_file(char* file_name)
{
	int fname_len = 0;
	int fdata_len = 0;

	int cur_len = 0;
	int tmp_len = 0;
	char rec_buf[1024] = {0};
	char tmp_buf[4096] = {0};

	int send_len = 0;
	char send_buf[4096] = {0};

	unsigned short chksum = 0;

    FILE *fp = fopen(file_name, "r");  
    if (fp == NULL)  
    {  
        printf("File:\t%s Can Not Open To Write!\n", file_name);  
        return -1;  
    }  
	printf("%s\n", file_name);

	while ((tmp_len = fread(rec_buf, sizeof(char), BUFFER_SIZE, fp)) > 0)
	{
		printf("tmplen:%d\n", tmp_len);
		strncpy(tmp_buf+cur_len, rec_buf, tmp_len);

	//printf("==================================\n");
	//printf("tmpbuf in clrcle is:\n");
	//printf("%s\n", tmp_buf);
	//printf("==================================\n");

		cur_len = cur_len + tmp_len;	

		//bzero(rec_buf, sizeof(rec_buf));
	}
	
	fname_len = strlen(file_name);
	fdata_len = strlen(tmp_buf);
	printf("fdata_len is:%d\n", fdata_len);

	send_len = sizeof(send_len) + sizeof(fname_len) + fname_len + sizeof(fdata_len) + fdata_len + sizeof(chksum);

	memcpy(send_buf , &send_len, sizeof(int));
	memcpy(send_buf + sizeof(int), &fname_len, sizeof(int));
	memcpy(send_buf + 2*sizeof(int), file_name, fname_len);
	memcpy(send_buf + 2*sizeof(int) + fname_len, &fdata_len, sizeof(int));
	memcpy(send_buf + 3*sizeof(int) + fname_len, tmp_buf, fdata_len);
	
	chksum = cal_chksum( (unsigned short *)tmp_buf, fdata_len); /*校验算法*/
	printf("chksum:%d\n", chksum);
	memcpy(send_buf + 3*sizeof(int) + fname_len + fdata_len, &chksum, sizeof(unsigned short));

	printf("==================================\n");
	printf("disbuf:\n");
	t_disbuf(send_buf, send_len + 4);
	printf("==================================\n");
	
	if (send_data(send_buf, send_len) < 0)
	{
		printf("senddata failed\n");
		return -1;
	}

	fclose(fp);
}

//int read_sock_conf(*ip, *port)
//{
	/*
	if (inet_aton(ip, &server_addr.sin_addr) == 0)  
    {  
        printf("Server IP Address Error!\n");  
        exit(1);  
    }  

    server_addr.sin_port = htons(HELLO_WORLD_SERVER_PORT);  
	*/

//	return 1;	
//}

int init_sock()
{
	//unsigned long  s_ip; 
	//unsigned short s_port;

//	if (read_sock_conf(&ip, &port) < 0)
//		return -1;

	struct sockaddr_in   server_addr;  
    bzero(&server_addr, sizeof(server_addr));  
    socklen_t server_addr_length = sizeof(server_addr);  

    server_addr.sin_family = AF_INET;  
    server_addr.sin_addr.s_addr = htons(INADDR_ANY);  
    server_addr.sin_port = htons(HELLO_WORLD_SERVER_PORT);  

	int server_socket = socket(PF_INET, SOCK_STREAM, 0);  
    if (server_socket < 0)  
    {  
        printf("Create Socket Failed!\n");  
		return -1;
    }  
   
	if (connect(server_socket, (struct sockaddr*)&server_addr, server_addr_length) < 0)  
    {  
        printf("Connect error!\n");  
		return -1;
    }  
  
	return server_socket;
}

//part2
int send_data(char *send_buf, int send_len)
{
	int n = 0;
		
	int s_socket = init_sock();
	if (s_socket < 0) 
	{
		printf("connect socket failed\n");
		return -1;
	}
    
	n = send(s_socket, send_buf, send_len, 0);
	printf("send len is:%d\n", n);
	if (n < 0)
	{
		printf("send failed\n");
		return -1;
	}

	close(s_socket);
	return 1;
}

int main(int argc, char **argv)  
{  
	par_args(argc, argv);
	pars_filename(argc, argv);

	return 0;  
}  
