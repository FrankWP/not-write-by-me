#include<netinet/in.h>  
#include<sys/types.h>  
#include<sys/socket.h>  
#include<stdio.h>  
#include<stdlib.h>  
#include<string.h>  
  
#define HELLO_WORLD_SERVER_PORT    5000  
#define LENGTH_OF_LISTEN_QUEUE     20  
#define BUFFER_SIZE                1024  
#define FILE_NAME_MAX_SIZE         512  
	

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


int init_sock()
{
	struct sockaddr_in   server_addr;  
    bzero(&server_addr, sizeof(server_addr));  
    server_addr.sin_family = AF_INET;  
    server_addr.sin_addr.s_addr = htons(INADDR_ANY);  
    server_addr.sin_port = htons(HELLO_WORLD_SERVER_PORT);  
  
    int server_socket = socket(PF_INET, SOCK_STREAM, 0);  
    if (server_socket < 0)  
    {  
        printf("Create Socket Failed!\n");  
        exit(1);  
    }  
  
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)))  
    {  
        printf("Server Bind Port: %d Failed!\n", HELLO_WORLD_SERVER_PORT);  
        exit(1);  
    }  
    socklen_t server_addr_length = sizeof(server_addr);  
 
    if (listen(server_socket, LENGTH_OF_LISTEN_QUEUE))  
    {  
        printf("Server Listen Failed!\n");  
		return -1;
    }  

	return server_socket;
}

//part2 recive and write single file

int recv_data()
{
	struct sockaddr_in   client_addr;  
    socklen_t length = sizeof(client_addr);  

	int server_socket = init_sock();	
	if (server_socket < 0)
	{
		printf("create socket failed!\n");
		return -1;
	}

	while (1)
	{
		int new_server_socket = accept(server_socket, (struct sockaddr*)&client_addr, &length);  
        if (new_server_socket < 0)  
        {  
            printf("Server Accept Failed!\n");  
            break;  
        }  

		int recv_len = 0;
		int total_len = 0;
		int tmp_len = 0;
		char buffer[BUFFER_SIZE] = {0};  
		char file_buf[4096] = {0};

        length = recv(new_server_socket, buffer, sizeof(int), 0);  
        if (length < 0)  
        {  
            printf("Server Recieve Data Failed!\n");  
            break;  
        }  
		printf("length:%d\n", length);
		memcpy(&total_len, buffer, 4);
		total_len -= 4;
		printf("total_len:%d\n", total_len);

		while (tmp_len != total_len)
		{	
			recv_len = recv(new_server_socket, buffer, BUFFER_SIZE , 0);  
			if (recv_len < 0)  
			{  
				printf("Server Recieve Data Failed!\n");  
				break;  
			}  
			
			memcpy(file_buf + tmp_len, buffer, recv_len);
			tmp_len = tmp_len + recv_len;	
			printf("tmp_len is :%d\n", tmp_len);
		}

		puts("===================================");
		puts("recv:");
		t_disbuf(file_buf, total_len);
		puts("===================================");

		write_new_file(file_buf, total_len);
		close(new_server_socket);
	}

	close(server_socket);
}

int write_new_file(char *file_buf, int file_len)
{
	puts("===================================");
	puts("recv:");
	t_disbuf(file_buf, file_len);
	puts("===================================");

	int tmp_len = 0;

	int fname_len = 0;
	int fdata_len = 0;

	int write_len = 0;

	char fname[256] = {0};
	char fdata[4096] = {0};

   	memcpy(&fname_len, file_buf, sizeof(int));
	memcpy(fname, file_buf + sizeof(int), fname_len);

	memcpy(&fdata_len, file_buf + sizeof(int) + fname_len, sizeof(int));
	memcpy(fdata, file_buf + 2*sizeof(int) + fname_len, fdata_len);

	printf("fname is:%s\n", fname);
	puts("===================================");
	puts("fdata:");
	t_disbuf(fdata, fdata_len);
	puts("===================================");

	FILE *fp = fopen(fname, "w+");  
    if (fp == NULL)  
    {  
        printf("File:\t%s Can Not Open To Write!\n", fname);  
        return -1;  
    }  

	while (tmp_len < fdata_len)
	{
		write_len = fwrite(fdata, sizeof(char), fdata_len, fp);  
		tmp_len = tmp_len + write_len;
    } 

	fclose(fp);
	return 1;
}
  
int main(int argc, char **argv)  
{  
	if (recv_data() < 0)
		return -1;

   return 0;  
}
  
