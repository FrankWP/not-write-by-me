 
#define HELLO_WORLD_SERVER_PORT    5000  
#define LENGTH_OF_LISTEN_QUEUE     20  
#define BUFFER_SIZE                1024  
#define FILE_NAME_MAX_SIZE         512  

#include "syshead.h"
#include "md5.h"
#include "display.h"
#include "read_conf.h"


struct sock_conf sc;
const static char *sconf_file = "sock.conf";

char md5_src[33];
int write_new_file(char *file_buf, int file_len);
static void print_char(char ch);

char *MD5_file (char *path, int md5_len)
{
	FILE *fp = fopen (path, "rb");
	MD5_CTX mdContext;
	int bytes;
	unsigned char data[1024];
	char *file_md5;
	int i;

	if (fp == NULL) {
		fprintf (stderr, "fopen %s failed\n", path);
		return NULL;
	}

	//MD5_CTX mdContext;
	MD5Init (&mdContext);
	while ((bytes = fread (data, 1, 1024, fp)) != 0)
	{
		MD5Update (&mdContext, data, bytes);
	}
	MD5Final (&mdContext);

	file_md5 = (char *)malloc((md5_len + 1) * sizeof(char));
	if(file_md5 == NULL)
	{
		fprintf(stderr, "malloc failed.\n");
		return NULL;
	}
	memset(file_md5, 0, (md5_len + 1));

	if(md5_len == 16)
	{
		for(i=4; i<12; i++)
		{
			sprintf(&file_md5[(i-4)*2], "%02x", mdContext.digest[i]);
		}
	}
	else if(md5_len == 32)
	{
		for(i=0; i<16; i++)
		{
			sprintf(&file_md5[i*2], "%02x", mdContext.digest[i]);
		}
	}
	else
	{
		fclose(fp);
		free(file_md5);
		return NULL;
	}

	fclose (fp);
	return file_md5;
}

int move_conf(char *fsrc, char *fdst)
{
	printf("fsrc:%s fdst:%s\n", fsrc, fdst);
	FILE *stream;
	char cmd[256] = {0};
	char buf[1024] = {0};

	sprintf(cmd, "mv %s %s", fsrc, fdst);
	stream = popen(cmd, "r");
	if (stream == NULL)
	{
		printf("stream is null\n");
		return -1;
	}
	int ret = fread(buf, 1, sizeof(buf), stream);
	if (ret == 0)
		printf("rename success\n");
	else
		printf("rename failed\n");

	pclose(stream);

	return ret;
}
	
//part1 init socket

int init_sock(unsigned int s_ip, unsigned short s_port)
{
	struct sockaddr_in   server_addr;  
    memset(&server_addr, 0x00, sizeof(server_addr));  
    server_addr.sin_family = AF_INET;  
    server_addr.sin_addr.s_addr = htonl(s_ip);  
    server_addr.sin_port = htons(s_port);  
  
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

int init_conf()
{
	char *val = NULL;
    struct	sockaddr_in s_addr;

	query_conf *general = NULL;
	query_conf *conf = NULL;

	if ((conf = load_configuration(sconf_file)) == NULL)
	{
        return -1;
	}

	if ((general = find_label(conf, (char*)"socket")) == NULL)
	{
		free_configuration(&conf);
		return -1;
	}
	
	if ((val = get_value_from_label(general, (char*)"synconf_ip")) != NULL)
        sc.s_ip = inet_atoul(val);
	printf("ip:%s\n", val);

	if ((val = get_value_from_label(general, (char*)"synconf_port")) != NULL)
        sc.s_port = (unsigned short int)atoi(val);
	printf("port:%d\n", sc.s_port);
	
	free_configuration(&conf);

	return 0;
}

int recv_data()
{
	puts("---------1");
	struct sockaddr_in   client_addr;  
    socklen_t length = sizeof(client_addr);  
        
	//sc.s_ip = inet_atoul(val);
    //sc.s_port = (unsigned short)atoi(val);

	if (init_conf() < 0)
		return -1;

	puts("---------2");
	int server_socket = init_sock(sc.s_ip, sc.s_port);	
	if (server_socket < 0)
	{
		printf("create socket failed!\n");
		return -1;
	}

	puts("---------3");
	while (1)
	{
	puts("---------4");
		int new_server_socket = accept(server_socket, (struct sockaddr*)&client_addr, &length);  
	puts("---------5");
        if (new_server_socket < 0)  
        {  
            printf("Server Accept Failed!\n");  
            break;  
        }  
		else
			puts("connect come");
	puts("---------6");

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
	char ftmp[256] = {0};

	unsigned short chk_src = 0;
	unsigned short chk_dst = 0;

	memcpy(&fname_len, file_buf, sizeof(int));
	memcpy(fname, file_buf + sizeof(int), fname_len);

	memcpy(&fdata_len, file_buf + sizeof(int) + fname_len, sizeof(int));
	memcpy(fdata, file_buf + 2*sizeof(int) + fname_len, fdata_len);

	memcpy(md5_src, file_buf + 2*sizeof(int) + fname_len + fdata_len, 32);

	printf("fname is:%s\n", fname);
	puts("===================================");
	puts("fdata:");
	t_disbuf(fdata, fdata_len);
	puts("===================================");

	printf("recv md5 src:%s\n", md5_src);

	sprintf(ftmp, ".%s.tmp", fname);
	printf("tmp name:%s\n", ftmp);

	FILE *fp = fopen(ftmp, "w+");  
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
	
	char * md5_dst = MD5_file(ftmp, 32);

	printf("md5src:%s md5dst:%s", md5_dst, md5_src);
	if (!memcmp(md5_dst, md5_src, 32)) 
	{
		printf("md5 is same\n");
		//
		//system("mv tmp_file file");
		if (move_conf(ftmp, fname) < 0)
			printf("move file failed");
		free(md5_dst);
	}
	else
	{
		printf("md5 is not same\n");
		//file is wrong
		free(md5_dst);
	}

	return 1;
}

int main(int argc, char **argv)  
{  
	if (recv_data() < 0)
		return -1;

   return 0;  
}
  
