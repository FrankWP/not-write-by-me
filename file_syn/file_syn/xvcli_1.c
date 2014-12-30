#include "syshead.h"
#include "md5.h"
#include "display.h"
#include "read_conf.h"
  
#define BUFFER_SIZE                   1024  

int get_fname_from_args(char* file_name);
int send_data(char *send_buf, int send_len);

struct sock_conf sc;
const static char *sconf_file = "sock.conf";

//¶ÁÈ¡ÅäÖÃÎÄ¼þ²ÎÊý
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
        sc.s_port = (unsigned short)atoi(val);
	printf("port:%d\n", sc.s_port);

	free_configuration(&conf);

	return 0;
}

//²ÎÊýÖÐ£¬ÖÁÉÙ°üº¬Ò»¸öÎÄ¼þÃû
void parse_args(int argc, char **argv)
{
	if (argc < 2)  
    {  
        printf("Usage: ./%s ConfigName[1] ConfigName[2]... \n", argv[0]);  
        exit(1);  
    }  
}

//´Ó²ÎÊýÁÐ±íÖÐ£¬Öð¸ö¶ÁÈ¡ÅäÖÃÎÄ¼þµÄÃû×Ö¡
void parse_fname(int argc, char **argv)
{
	int i;
	for (i=1; i<argc; i++)
	{
		if (get_fname_from_args(argv[i]) < 0)
		{
			printf("read synchronous config file %s failed!\n", argv[i]);
			continue;
		}
	}		
}

//´Ó²ÎÊýÁÐ±íÖÐ»ñÈ¡Í¬²½ÎÄ¼þÃûµÄ¼¯ºÏ
//·¢ËÍ¸ñÊ½Îª£º
//ÎÄ¼þ×Ü³¤¶È(int)+ÎÄ¼þÃû³¤¶È(int)+ÎÄ¼þÃû+Êý¾Ý³¤¶È(int)+Êý¾Ý+ÎÄ¼þMD5Öµ(32ÎÎ»)
int get_fname_from_args(char* file_name)
{
	int i;
	int fname_len = 0;
	int fdata_len = 0;

	int cur_len = 0;
	int tmp_len = 0;

	char rec_buf[1024] = {0};
	char tmp_buf[4096] = {0};
	char file_md5[32] = {0};

	int send_len = 0;
	char send_buf[4096] = {0};
	
	MD5_CTX mdContext;
	MD5Init (&mdContext);

    FILE *fp = fopen(file_name, "r");  
    if (fp == NULL)  
    {  
        printf("File:\t%s Can Not Open To Write!\n", file_name);  
        return -1;  
    }  

	while ((tmp_len = fread(rec_buf, sizeof(char), BUFFER_SIZE, fp)) > 0)
	{
		strncpy(tmp_buf+cur_len, rec_buf, tmp_len);
		cur_len = cur_len + tmp_len;	
	}
	
	fname_len = strlen(file_name);
	fdata_len = strlen(tmp_buf);

	MD5Update (&mdContext, tmp_buf, fdata_len);
	MD5Final (&mdContext);

	send_len = sizeof(send_len) + sizeof(fname_len) + fname_len + sizeof(fdata_len) + fdata_len + 32;

	memcpy(send_buf , &send_len, sizeof(int));
	memcpy(send_buf + sizeof(int), &fname_len, sizeof(int));
	memcpy(send_buf + 2*sizeof(int), file_name, fname_len);
	memcpy(send_buf + 2*sizeof(int) + fname_len, &fdata_len, sizeof(int));
	memcpy(send_buf + 3*sizeof(int) + fname_len, tmp_buf, fdata_len);

	for(i=0; i<16; i++)
	{
		sprintf(&file_md5[i*2], "%02x", mdContext.digest[i]);
	}

	memcpy(send_buf + 3*sizeof(int) + fname_len + fdata_len, file_md5, 32);

	if (send_data(send_buf, send_len) < 0)
	{
		printf("senddata failed\n");
		return -1;
	}

	fclose(fp);
}

//³õÊ¼»¯socketÐÅÏ¢
int init_sock(unsigned int s_ip, unsigned short s_port)
{
	struct sockaddr_in   server_addr;  
    memset(&server_addr, 0x00, sizeof(server_addr));  
    socklen_t server_addr_length = sizeof(server_addr);  

    server_addr.sin_family = AF_INET;  
    server_addr.sin_addr.s_addr = htonl(s_ip);  
    server_addr.sin_port = htons(s_port);  

	int server_socket = socket(PF_INET, SOCK_STREAM, 0);  
    if (server_socket < 0)  
    {  
		return -1;
    }  
   
	if (connect(server_socket, (struct sockaddr*)&server_addr, server_addr_length) < 0)  
    {  
        printf("Connect error!\n");  
		return -1;
    }  
  
	return server_socket;
}

//·¢ËÍsocketÊý¾Ý
int send_data(char *send_buf, int send_len)
{
	int n = 0;

	if (init_conf() < 0)
		return -1;
		
	int s_socket = init_sock(sc.s_ip, sc.s_port);
	if (s_socket < 0) 
	{
		printf("connect socket failed\n");
		return -1;
	}
    
	n = send(s_socket, send_buf, send_len, 0);
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
	parse_args(argc, argv);
	parse_fname(argc, argv);

	return 0;  
}  
