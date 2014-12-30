#define LENGTH_OF_LISTEN_QUEUE     20  
#define BUFFER_SIZE                1024  

#include "syshead.h"
#include "md5.h"
#include "display.h"
#include "read_conf.h"

//socket配置文集结构
struct sock_conf sc;
const static char *sconf_file = "sock.conf";

char md5_src[33];
int write_new_file(char *file_buf, int file_len);
static void print_char(char ch);

//获取文件的MD5信息
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

//用临时文件替换掉原有的配置文件
int replace_conf_file(char *fsrc, char *fdst)
{
	FILE *stream;
	char cmd[128] = {0};
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
	
//初始化socket配置
int init_sock_conf(unsigned int s_ip, unsigned short s_port)
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
		return -1;
    }  
  
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)))  
    {  
        printf("Server Bind Port: %d Failed!\n", server_addr.sin_port);  
		return -1;
    }  
    socklen_t server_addr_length = sizeof(server_addr);  
 
    if (listen(server_socket, LENGTH_OF_LISTEN_QUEUE))  
    {  
        printf("Server Listen Failed!\n");  
		return -1;
    }  

	return server_socket;
}

//初始化socket配置文件,获取监听服务的IP和端口
int read_sock_conf()
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

	if ((val = get_value_from_label(general, (char*)"synconf_port")) != NULL)
        sc.s_port = (unsigned short int)atoi(val);
	
	free_configuration(&conf);

	return 0;
}

//收取从客户端传输过来的文件流，按照文件流的单个总长度接收配置文件，并将单个文件进行解析。
//将文件流写入新临时文件中，如果临时文件的MD5值与文件流中的MD5值相同，
//则替换掉原有的配置文件，如果不相同，则不进行替换。
int recv_file_data()
{
	struct sockaddr_in   client_addr;  
    socklen_t length = sizeof(client_addr);  
        
	if (read_sock_conf() < 0)
		return -1;

	int server_socket = init_sock_conf(sc.s_ip, sc.s_port);	
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

		int fname_len = 0;
		int fdata_len = 0;
		int write_len = 0;

		char fname[256] = {0};
		char fdata[4096] = {0};
		char ftmp[256] = {0};

		unsigned short chk_src = 0;
		unsigned short chk_dst = 0;

		char buffer[BUFFER_SIZE] = {0};  
		char file_buf[4096] = {0};

		//接收总长度及文件长度
        length = recv(new_server_socket, buffer, 2*sizeof(int), 0);  
        if (length < 0)  
        {  
            printf("Server Recieve Data Failed!\n");  
            break;  
        }  
		memcpy(&total_len, buffer, sizeof(int));
		total_len -= 4;
		memcpy(&fname_len, buffer + sizeof(int), sizeof(int));

		//接收文件名
		length = recv(new_server_socket, buffer, fname_len, 0);  
        if (length < 0)  
        {  
            printf("Server Recieve Data Failed!\n");  
            break;  
        } 
		memcpy(fname, buffer, fname_len);
		
		//接收数据长度
		length = recv(new_server_socket, buffer, sizeof(int), 0);  
        if (length < 0)  
        {  
            printf("Server Recieve Data Failed!\n");  
            break;  
        } 
		memcpy(&fdata_len, buffer, sizeof(int));

		//打开临时文件
		sprintf(ftmp, ".%s.tmp", fname);
		FILE *fp = fopen(ftmp, "w+");  
		if (fp == NULL)  
		{  
			printf("File:\t%s Can Not Open To Write!\n", fname);  
			return -1;  
		}  

		//接收文件数据，同时写入文件
		length = 0;
		int rtmp_len;
		while(fdata_len != 0)
		{
			rtmp_len = (fdata_len < BUFFER_SIZE)?fdata_len:BUFFER_SIZE;
			length = recv(new_server_socket, buffer, rtmp_len, 0);
			if (length < 0)  
			{  
				printf("Recieve Data From Server Failed!\n");  
				break;  
			}  
			
			fdata_len = fdata_len - length;

			int write_length = fwrite(buffer, sizeof(char), length, fp);  
			if (write_length < length)  
			{  
				printf("File:\t%s Write Failed!\n", ftmp);  
				break;  
			}  

			memset(buffer, 0x00, BUFFER_SIZE);  
		}  
		
		fclose(fp);
		
		//接收MD5值
		length = recv(new_server_socket, buffer, 32, 0);  
        if (length < 0)  
        {  
            printf("Server Recieve Data Failed!\n");  
            break;  
        } 

		memcpy(md5_src, buffer, 32);

		char * md5_dst = MD5_file(ftmp, 32);
		printf("md5_dst:%s\n md5_src:%s\n", md5_dst, md5_src);
		if (!memcmp(md5_dst, md5_src, 32)) 
		{
			if (replace_conf_file(ftmp, fname) < 0)
				printf("move file failed");
			free(md5_dst);
		}
		else
		{
			printf("md5 is not same\n");
			//文件MD5值不相同
			free(md5_dst);
		}

		close(new_server_socket);
	}
	close(server_socket);
}


int main(int argc, char **argv)  
{  
	if (recv_file_data() < 0)
		return -1;

   return 0;  
}
  
