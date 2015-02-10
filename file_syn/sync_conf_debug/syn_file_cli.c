/*******************************************************
 *
 * Copyright(c) 2006-2015 Legendsec Technology Co., Ltd.  
 * All rights reserved
 *
 * File Name: syn_file_ser.c 
 * Function Description: 
 *		The file sended by opposite device is recived by this function.
 *		if the MD5 of the file changed during transmission, this file
 *		will be discarded.
 * Current Version: 1.0
 * Author： wangyonga
 * Creation Date：2015.1.29
 * Modify History：None
 *
 *
 * *******************************************************/

#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <dlfcn.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <signal.h>
#include <stdio.h>               
#include <stdlib.h>             
#include <string.h>            
#include <stdarg.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <sys/types.h>              
#include <sys/socket.h>            
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/in.h>              

#include "display.h"
#include "mlog.h"

#define true 1
#define false 0


#define SYNC_PKG_HEAD_FLG		"sync"

#define SYNC_MOD_NAME	"文件同步"

#define SYNC_LOGNT_START_CLI	"文件同步客户端服务开启"
#define SYNC_LOGNT_FINISH_SEND	"文件同步客户端发送配置文件完毕"

#define SYNC_LOGERR_READ_LABEL	"文件同步读取配置文件标签错误"
#define SYNC_LOGERR_LOAD_LABEL	"文件同步加载配置文件错误!"
#define SYNC_LOGERR_LOAD_ITEM	"文件同步加载配置列表文件失败或文件为空!"

#define SYNC_LOGERR_FILE_DEAL		"文件同步处理同步文件失败!"
#define SYNC_LOGERR_FILE_CANT_READ	"文件同步文件无法打开"

#define SYNC_LOGERR_SOCK_SEND	"文件同步网络发送数据失败!"
#define SYNC_LOGERR_SOCK_INIT	"文件同步初始化套接字失败!"
#define SYNC_LOGERR_SOCK_CONN	"文件同步无法进行网络连接!"
#define SYNC_LOGERR_SOCK_LOAD_LABEL	"文件同步加载网络配置文件错误!"
#define SYNC_LOGERR_SOCK_READ_LABEL	"文件同步加载网络配置列表文件失败或文件为空!"


/* buffer size of recive file */
#define BUFFER_SIZE                   1024  

/* the module config file of File Synchronization Module */
static char *sync_mod_conf_path = "/storage/hawk/ha/sync_config/syn_mod.conf";

/* the module label value of File Synchronization Module */
static char *sync_mod_conf_label = "mod";

/* the item config file of File Synchronization Module */
static char *sync_items_conf_path = "/storage/hawk/ha/sync_config/syn_item.conf";

/* the Net config file of File Synchronization Module */
static char *sync_sock_conf_path = "/storage/hawk/ha/sync_config/sync_sock.conf";

/* the client label name in Net config file */
static char *sync_sock_conf_label = "syncli";

/* the server ip to be connected in Net config file */
static char *sync_sock_conf_ip = "sync_sock_cli_ip";

/* the server port to be connected in Net config file */
static char *sync_sock_conf_port = "sync_sock_cli_port";

typedef unsigned long int UINT4;
static unsigned char PADDING[64] = {
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* F, G and H are basic MD5 functions: selection, majority, parity */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z))) 

/* ROTATE_LEFT rotates x left n bits */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4 */
/* Rotation is separate from addition to prevent recomputation */
#define FF(a, b, c, d, x, s, ac) \
{(a) += F ((b), (c), (d)) + (x) + (UINT4)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
}
#define GG(a, b, c, d, x, s, ac) \
{(a) += G ((b), (c), (d)) + (x) + (UINT4)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
}
#define HH(a, b, c, d, x, s, ac) \
{(a) += H ((b), (c), (d)) + (x) + (UINT4)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
}
#define II(a, b, c, d, x, s, ac) \
{(a) += I ((b), (c), (d)) + (x) + (UINT4)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
}


typedef struct __sync_conf_items
{
	char *item_name;
	char *item_value;
	struct __sync_conf_items *item_next;
} sync_conf_items_t;

typedef struct __sync_conf_labels
{
	char *label_name;
	sync_conf_items_t *label_item;
	struct __sync_conf_labels *label_next;
} sync_conf_labels_t;

typedef struct __sync_conf_sock
{
	unsigned int s_ip;
	unsigned short s_port;
} sync_conf_sock_t;
sync_conf_sock_t sync_sock_addr;

typedef struct __sync_pkg_head
{
	char sync_pkg_head_flg[4];
	int  sync_pkg_file_name_len;
	int  sync_pkg_file_cont_len;
	char sync_pkg_file_md5[64];
	char sync_pkg_file_name[256];
	char sync_pkg_file_cont[0];
}sync_pkg_head_t;

typedef struct {
	UINT4 i[2];                   /* number of _bits_ handled mod 2^64 */
	UINT4 buf[4];                                    /* scratch buffer */
	unsigned char in[64];                              /* input buffer */
	unsigned char digest[16];     /* actual digest after sync_cli_md5_final call */
} MD5_CTX;

/* deal with configuration functions, include load , read and free conf file*/
sync_conf_labels_t * sync_cli_load_conf_file(const char *filepath);
char *sync_cli_pre_deal_line(char *line);
char *sync_cli_trim_conf_line(char *str);
char *sync_cli_load_conf_line(char *cursor, char *store, int storesz);
char *sync_cli_get_label_value(sync_conf_labels_t *que, char *item_name);
sync_conf_labels_t *sync_cli_load_conf_label(sync_conf_labels_t *p_sync_conf_labels_t, 
		char *label_name);
static sync_conf_items_t *sync_cli_deal_item_line(char *read_line, 
		sync_conf_labels_t **p_conf_que, 
		sync_conf_items_t **p_item_tail);
static sync_conf_labels_t *sync_cli_deal_label_line(char *read_line, 
		sync_conf_labels_t **p_conf_head, 
		sync_conf_labels_t **p_conf_tail);
int sync_cli_deal_item_value(sync_conf_labels_t *que, char *item_name);
int sync_cli_deal_label_value(sync_conf_labels_t *que, char *item_name);
void sync_cli_free_conf_file(sync_conf_labels_t **pque);

/* deal file functions, include read local file ,package it and send it */
int sync_cli_start_parse_file(int argc, char **argv);
int sync_cli_pkg_single_file(char* file_name);
int sync_cli_send_file_data(char *file_name, char *send_buf, int send_len);

/* socket functions, include trans net address format, read and init socket */
unsigned int sync_cli_trans_inet_atoul(const char * s);
char * sync_cli_trans_inet_ultoa(unsigned int u, char * s);
int sync_cli_read_sock_conf();
int sync_cli_init_sock(unsigned int s_ip, unsigned short s_port);

/* md5 functions ,get file md5 values*/
void sync_cli_md5_init (MD5_CTX *mdContext);
void sync_cli_md5_update (MD5_CTX *mdContext, unsigned char *inBuf, unsigned int inLen);
static void sync_cli_md5_transform (UINT4 *buf, UINT4 *in);
void sync_cli_md5_final (MD5_CTX *mdContext);

void sync_cli_md5_init (MD5_CTX *mdContext)
{
	mdContext->i[0] = mdContext->i[1] = (UINT4)0;

	mdContext->buf[0] = (UINT4)0x67452301;
	mdContext->buf[1] = (UINT4)0xefcdab89;
	mdContext->buf[2] = (UINT4)0x98badcfe;
	mdContext->buf[3] = (UINT4)0x10325476;
}

void sync_cli_md5_update (MD5_CTX *mdContext, unsigned char *inBuf, unsigned int inLen)
{
	UINT4 in[16];
	int mdi;
	unsigned int i, ii;

	mdi = (int)((mdContext->i[0] >> 3) & 0x3F);
	if ((mdContext->i[0] + ((UINT4)inLen << 3)) < mdContext->i[0])
		mdContext->i[1]++;
	mdContext->i[0] += ((UINT4)inLen << 3);
	mdContext->i[1] += ((UINT4)inLen >> 29);

	while (inLen--) {
		mdContext->in[mdi++] = *inBuf++;

		if (mdi == 0x40) {
			for (i = 0, ii = 0; i < 16; i++, ii += 4)
				in[i] = (((UINT4)mdContext->in[ii+3]) << 24) |
					(((UINT4)mdContext->in[ii+2]) << 16) |
					(((UINT4)mdContext->in[ii+1]) << 8) |
					((UINT4)mdContext->in[ii]);
			sync_cli_md5_transform (mdContext->buf, in);
			mdi = 0;
		}
	}
}

void sync_cli_md5_final (MD5_CTX *mdContext)
{
	UINT4 in[16];
	int mdi;
	unsigned int i, ii;
	unsigned int padLen;

	in[14] = mdContext->i[0];
	in[15] = mdContext->i[1];

	mdi = (int)((mdContext->i[0] >> 3) & 0x3F);

	padLen = (mdi < 56) ? (56 - mdi) : (120 - mdi);
	sync_cli_md5_update (mdContext, PADDING, padLen);

	for (i = 0, ii = 0; i < 14; i++, ii += 4)
		in[i] = (((UINT4)mdContext->in[ii+3]) << 24) |
			(((UINT4)mdContext->in[ii+2]) << 16) |
			(((UINT4)mdContext->in[ii+1]) << 8) |
			((UINT4)mdContext->in[ii]);
	sync_cli_md5_transform (mdContext->buf, in);

	for (i = 0, ii = 0; i < 4; i++, ii += 4) {
		mdContext->digest[ii] = (unsigned char)(mdContext->buf[i] & 0xFF);
		mdContext->digest[ii+1] =
			(unsigned char)((mdContext->buf[i] >> 8) & 0xFF);
		mdContext->digest[ii+2] =
			(unsigned char)((mdContext->buf[i] >> 16) & 0xFF);
		mdContext->digest[ii+3] =
			(unsigned char)((mdContext->buf[i] >> 24) & 0xFF);
	}
}

static void sync_cli_md5_transform (UINT4 *buf, UINT4 *in)
{
	UINT4 a = buf[0], b = buf[1], c = buf[2], d = buf[3];

	/* Round 1 */
#define S11 7
#define S12 12
#define S13 17
#define S14 22

	FF ( a, b, c, d, in[ 0], S11, 0xd76aa478); /* 1 */
	FF ( d, a, b, c, in[ 1], S12, 0xe8c7b756); /* 2 */
	FF ( c, d, a, b, in[ 2], S13, 0x242070db); /* 3 */
	FF ( b, c, d, a, in[ 3], S14, 0xc1bdceee); /* 4 */
	FF ( a, b, c, d, in[ 4], S11, 0xf57c0faf); /* 5 */
	FF ( d, a, b, c, in[ 5], S12, 0x4787c62a); /* 6 */
	FF ( c, d, a, b, in[ 6], S13, 0xa8304613); /* 7 */
	FF ( b, c, d, a, in[ 7], S14, 0xfd469501); /* 8 */
	FF ( a, b, c, d, in[ 8], S11, 0x698098d8); /* 9 */
	FF ( d, a, b, c, in[ 9], S12, 0x8b44f7af); /* 10 */
	FF ( c, d, a, b, in[10], S13, 0xffff5bb1); /* 11 */
	FF ( b, c, d, a, in[11], S14, 0x895cd7be); /* 12 */
	FF ( a, b, c, d, in[12], S11, 0x6b901122); /* 13 */
	FF ( d, a, b, c, in[13], S12, 0xfd987193); /* 14 */
	FF ( c, d, a, b, in[14], S13, 0xa679438e); /* 15 */
	FF ( b, c, d, a, in[15], S14, 0x49b40821); /* 16 */

	/* Round 2 */
#define S21 5
#define S22 9
#define S23 14
#define S24 20

	GG ( a, b, c, d, in[ 1], S21, 0xf61e2562); /* 17 */
	GG ( d, a, b, c, in[ 6], S22, 0xc040b340); /* 18 */
	GG ( c, d, a, b, in[11], S23, 0x265e5a51); /* 19 */
	GG ( b, c, d, a, in[ 0], S24, 0xe9b6c7aa); /* 20 */
	GG ( a, b, c, d, in[ 5], S21, 0xd62f105d); /* 21 */
	GG ( d, a, b, c, in[10], S22, 0x2441453);  /* 22 */
	GG ( c, d, a, b, in[15], S23, 0xd8a1e681); /* 23 */
	GG ( b, c, d, a, in[ 4], S24, 0xe7d3fbc8); /* 24 */
	GG ( a, b, c, d, in[ 9], S21, 0x21e1cde6); /* 25 */
	GG ( d, a, b, c, in[14], S22, 0xc33707d6); /* 26 */
	GG ( c, d, a, b, in[ 3], S23, 0xf4d50d87); /* 27 */
	GG ( b, c, d, a, in[ 8], S24, 0x455a14ed); /* 28 */
	GG ( a, b, c, d, in[13], S21, 0xa9e3e905); /* 29 */
	GG ( d, a, b, c, in[ 2], S22, 0xfcefa3f8); /* 30 */
	GG ( c, d, a, b, in[ 7], S23, 0x676f02d9); /* 31 */
	GG ( b, c, d, a, in[12], S24, 0x8d2a4c8a); /* 32 */

	/* Round 3 */
#define S31 4
#define S32 11
#define S33 16
#define S34 23

	HH ( a, b, c, d, in[ 5], S31, 0xfffa3942); /* 33 */
	HH ( d, a, b, c, in[ 8], S32, 0x8771f681); /* 34 */
	HH ( c, d, a, b, in[11], S33, 0x6d9d6122); /* 35 */
	HH ( b, c, d, a, in[14], S34, 0xfde5380c); /* 36 */
	HH ( a, b, c, d, in[ 1], S31, 0xa4beea44); /* 37 */
	HH ( d, a, b, c, in[ 4], S32, 0x4bdecfa9); /* 38 */
	HH ( c, d, a, b, in[ 7], S33, 0xf6bb4b60); /* 39 */
	HH ( b, c, d, a, in[10], S34, 0xbebfbc70); /* 40 */
	HH ( a, b, c, d, in[13], S31, 0x289b7ec6); /* 41 */
	HH ( d, a, b, c, in[ 0], S32, 0xeaa127fa); /* 42 */
	HH ( c, d, a, b, in[ 3], S33, 0xd4ef3085); /* 43 */
	HH ( b, c, d, a, in[ 6], S34, 0x4881d05); /* 44 */
	HH ( a, b, c, d, in[ 9], S31, 0xd9d4d039); /* 45 */
	HH ( d, a, b, c, in[12], S32, 0xe6db99e5); /* 46 */
	HH ( c, d, a, b, in[15], S33, 0x1fa27cf8); /* 47 */
	HH ( b, c, d, a, in[ 2], S34, 0xc4ac5665); /* 48 */

	/* Round 4 */
#define S41 6
#define S42 10
#define S43 15
#define S44 21

	II ( a, b, c, d, in[ 0], S41, 0xf4292244); /* 49 */
	II ( d, a, b, c, in[ 7], S42, 0x432aff97); /* 50 */
	II ( c, d, a, b, in[14], S43, 0xab9423a7); /* 51 */
	II ( b, c, d, a, in[ 5], S44, 0xfc93a039); /* 52 */
	II ( a, b, c, d, in[12], S41, 0x655b59c3); /* 53 */
	II ( d, a, b, c, in[ 3], S42, 0x8f0ccc92); /* 54 */
	II ( c, d, a, b, in[10], S43, 0xffeff47d); /* 55 */
	II ( b, c, d, a, in[ 1], S44, 0x85845dd1); /* 56 */
	II ( a, b, c, d, in[ 8], S41, 0x6fa87e4f); /* 57 */
	II ( d, a, b, c, in[15], S42, 0xfe2ce6e0); /* 58 */
	II ( c, d, a, b, in[ 6], S43, 0xa3014314); /* 59 */
	II ( b, c, d, a, in[13], S44, 0x4e0811a1); /* 60 */
	II ( a, b, c, d, in[ 4], S41, 0xf7537e82); /* 61 */
	II ( d, a, b, c, in[11], S42, 0xbd3af235); /* 62 */
	II ( c, d, a, b, in[ 2], S43, 0x2ad7d2bb); /* 63 */
	II ( b, c, d, a, in[ 9], S44, 0xe886d391); /* 64 */

	buf[0] += a;
	buf[1] += b;
	buf[2] += c;
	buf[3] += d;
}

void sync_cli_free_conf_item(sync_conf_items_t **item)
{
	sync_conf_items_t *item_tmp = NULL;
	if ((item == NULL) || (*item == NULL))
	{
		return;
	}

	item_tmp = *item;
	while (item_tmp != NULL)
	{
		*item = item_tmp;
		item_tmp = item_tmp->item_next;

		if ((*item)->item_name != NULL)
		{
			free((*item)->item_name);
		}
		if ((*item)->item_value != NULL)
		{
			free((*item)->item_value);
		}
		free(*item);
	}

	*item = NULL;
}

sync_conf_labels_t *sync_cli_load_conf_label(sync_conf_labels_t *p_sync_conf_labels_t, 
		char *label_name)
{
	sync_conf_labels_t *que = NULL;

	if ((p_sync_conf_labels_t == NULL) || (label_name == NULL))
	{
		printf("------------------NULL\n");
		return NULL;
	}

	for (que = p_sync_conf_labels_t; que != NULL; que = que->label_next)
	{
		printf("que->label name:%s, label_name:%s\n", que->label_name, label_name);
		if (strcmp(que->label_name, label_name) == 0)
		{
			break;
		}
	}

	return que;
}

char *sync_cli_get_label_value(sync_conf_labels_t *que, char *item_name)
{
	sync_conf_items_t *item = NULL;
	char *res = NULL;
	if ((que == NULL) || (item_name == NULL))
	{
		return NULL;
	}

	item = que->label_item;
	while (item != NULL)
	{
		if (strcmp(item->item_name, item_name) == 0)
		{
			res = item->item_value;
			break;
		}
		item = item->item_next;
	}

	return res;
}

char* sync_cli_trim_conf_line(char *str)
{
	char *base = NULL;
	char *curr = NULL;
	if (str == NULL)
	{
		return NULL;
	}

	base = str;
	curr = str;
	while (*curr != '\0')
	{
		if (isspace(*curr))
		{
			++curr;
			continue;
		}
		*base++ = *curr++;
	}
	*base = '\0';

	return str;
}

char * sync_cli_trans_inet_ultoa(unsigned int u, char * s)
{
	static char ss[20];

	if (s == NULL)
	{
		s = ss;
	}
	sprintf(s, "%d.%d.%d.%d",
			(unsigned int)(u>>24)&0xff, (unsigned int)(u>>16)&0xff,
			(unsigned int)(u>>8)&0xff, (unsigned int)u&0xff);
	return s;
}

unsigned int sync_cli_trans_inet_atoul(const char * s)
{
	int i;
	int u[4];
	unsigned int rv;

	if(sscanf(s, "%d.%d.%d.%d", &u[0], &u[1], &u[2], &u[3]) == 4) {
		for (i = 0, rv = 0; i < 4; i++) {
			rv <<= 8;
			rv |= u[i] & 0xff;
		}
		return rv;
	} else
		return 0xffffffff;
}

char *sync_cli_pre_deal_line(char *line)
{
	char *ptr = NULL;

	if (line == NULL){
		return NULL;
	}

	if ((ptr = strstr(line, "\n")) != NULL)
	{
		if (ptr - line > 1)
		{
			if (*(ptr - 1) == '\r')
				*(ptr - 1) = '\0';
		}
		*ptr = '\0';
	}

	if ((ptr = strstr(line, "#")) != NULL)
	{
		*ptr = '\0'; 
	}

	sync_cli_trim_conf_line(line);

	if (line[0] == '\0')
	{
		return NULL;
	}

	return line;
}

static sync_conf_labels_t *sync_cli_deal_label_line(char *read_line, 
		sync_conf_labels_t **p_conf_head, 
		sync_conf_labels_t **p_conf_tail)
{
	char name[64] = {0};
	sync_conf_labels_t *p_conf_que = NULL;

	if (strncmp(read_line, "[", 1) == 0)
	{
		if (strncmp(read_line, "[/", 2) == 0)
		{
			return NULL;
		}

		sscanf(read_line+1, "%[^]]", name);
		if (name[0] == '\0')
		{
			return NULL;
		}

		p_conf_que = (sync_conf_labels_t *)malloc(sizeof(sync_conf_labels_t));
		p_conf_que->label_name = strdup(name);
		p_conf_que->label_item = NULL;
		p_conf_que->label_next = NULL;

		if ((*p_conf_head) == NULL)
		{
			(*p_conf_head) = p_conf_que;
		}
		else
		{
			(*p_conf_tail)->label_next = p_conf_que;
		}
		(*p_conf_tail) = p_conf_que;

	}

	return *p_conf_tail;
}

static sync_conf_items_t *sync_cli_deal_item_line(char *read_line, 
		sync_conf_labels_t **p_conf_que, 
		sync_conf_items_t **p_item_tail)
{
	char name[64] = {0};
	char value[512] = {0};
	char *p_equal_sign = NULL;

	if ((read_line == NULL) || (p_conf_que == NULL) || (*p_conf_que == NULL) || (p_item_tail == NULL))
	{
		return NULL;
	}

	if ((p_equal_sign = strchr(read_line, '=')) != NULL)
	{
		name[0] = '\0';
		value[0] = '\0';

		if ((*p_conf_que)->label_name[0] == '\0')
		{
			return NULL;
		}

		if ( p_equal_sign[1] == '\0')
		{
			sscanf(read_line, "%[^=]", name);
			sprintf(value, "%s", "");
		}
		else
		{
			sscanf(read_line, "%[^=]", name);
			p_equal_sign += 1;
			sscanf(p_equal_sign, "%[^ ]", value);
		}

		sync_conf_items_t *p_item_node = (sync_conf_items_t *)malloc(sizeof(sync_conf_items_t));
		p_item_node->item_name = strdup(name);
		p_item_node->item_value = strdup(value);
		p_item_node->item_next = NULL;

		if ((*p_conf_que)->label_item == NULL) 
		{
			(*p_conf_que)->label_item = p_item_node;
		}
		else 
		{
			(*p_item_tail)->item_next = p_item_node;
		}
		*p_item_tail = p_item_node;
	}

	return *p_item_tail;
}

char* sync_cli_load_conf_line(char *cursor, char *store, int storesz)
{
	char *ptr = NULL;
	int size = 0;

	if ((cursor == NULL) || (store == NULL) || (storesz <= 0))
	{
		return NULL;
	}
	if (*cursor == '\0')
	{
		store[0] = '\0';
		return NULL;
	}

	ptr = strstr(cursor, "\n");
	if (ptr != NULL)
	{
		if (ptr - cursor > storesz - 1)
		{
			return NULL;
		}
		memcpy(store, cursor, ptr - cursor + 1);
		ptr += 1;
		if (*ptr == '\0') 
		{
			return NULL;
		}
	}
	else
	{
		size = strlen(cursor);
		if (size > storesz - 1) 
		{
			return NULL;
		}
		strcpy(store, cursor);
	}

	return ptr;
}

sync_conf_labels_t * sync_cli_load_conf_file(const char *filepath)
{
	FILE *fp = NULL;

	char read_line[2048] = {0};
	char *line_flg = NULL;
	char *pBuf = NULL;
	char *pFlg = NULL;

	struct stat fs;
	size_t filesz = 0;

	long nread = 0;

	sync_conf_labels_t *p_conf_head = NULL;
	sync_conf_labels_t *p_conf_tail = NULL;
	sync_conf_items_t *p_item_tail = NULL;

	if (filepath == NULL) 
	{
		return NULL;
	}

	if ((fp = fopen(filepath, "r")) == NULL)
	{
		return NULL;
	}

	fstat(fp->_fileno, &fs);
	filesz = fs.st_size;
	if (filesz == 0)
	{
		fclose(fp);
		return NULL;
	}
	pBuf = (char*)malloc(filesz);
	if (pBuf == NULL)
	{
		fclose(fp);
		return NULL;
	}
	nread = fread(pBuf, filesz, 1, fp);
	if (nread != 1)
	{
		fclose(fp);
		free(pBuf);
		return NULL;
	}

	pFlg = strstr(pBuf, "[");
	if (pFlg == NULL)
	{

	}
	else 
		pFlg = strstr(pFlg, "]");
	if (pFlg == NULL)
	{
		char *general_name = (char*)malloc(32);
		p_conf_head = (sync_conf_labels_t *)malloc(sizeof(sync_conf_labels_t));
		strcpy(general_name, "default");
		p_conf_head->label_name = general_name;
		p_conf_head->label_item = NULL;
		p_conf_head->label_next = NULL;
		p_conf_tail = p_conf_head;
	}

	pFlg = pBuf;
	while ((pFlg = sync_cli_load_conf_line(pFlg, read_line, sizeof(read_line))) != NULL)
	{
		line_flg = sync_cli_pre_deal_line(read_line);
		if (line_flg == NULL)
		{
			continue;
		}

		if (strncmp(read_line, "[", 1) == 0)
		{
			if (sync_cli_deal_label_line(read_line, &p_conf_head, &p_conf_tail) == NULL)
				continue;
		}

		if (strstr(read_line, "=") != NULL)
		{
			if (sync_cli_deal_item_line(read_line, &p_conf_tail, &p_item_tail) == NULL)
				continue; 
		}

		memset(read_line, 0, sizeof(read_line));
	}

	if (p_item_tail != NULL)
	{
		p_item_tail->item_next = NULL;
	}
	if (p_conf_tail != NULL)
	{
		p_conf_tail->label_next = NULL;
	}

	return p_conf_head;
}

void sync_cli_free_conf_file(sync_conf_labels_t **pque)
{
	sync_conf_labels_t *que = NULL;

	if ((pque == NULL) || (*pque == NULL))
	{
		return;
	}

	que = *pque;
	while (que != NULL)
	{
		*pque = que;
		que = que->label_next;

		sync_cli_free_conf_item(&((*pque)->label_item));
	}
	*pque = NULL;
}

int sync_cli_deal_label_value(sync_conf_labels_t *que, char *item_name)
{
	sync_conf_items_t *item = NULL;

	sync_conf_labels_t *mod_item_label_name = NULL;
	sync_conf_labels_t *mod_items_conf = NULL;
	if ((que == NULL) || (item_name == NULL))
	{
		return false;
	}

	if ((mod_items_conf = sync_cli_load_conf_file(sync_items_conf_path)) == NULL)
	{
		//printf("文件同步加载配置文件失败！\n");
		dmanage_log_err(PRE_HAWK_LOG "act=\"%s\" msg=\"%s\" filename=\"%s\"", 
				SYNC_MOD_NAME, SYNC_LOGERR_LOAD_ITEM, sync_items_conf_path);

		return false;
	}

	item = que->label_item;
	while (item != NULL)
	{
		if (strcmp(item->item_value, "yes") == 0)
		{
			printf("--------------itemname:%s\n", item->item_name);
			if ((mod_item_label_name = sync_cli_load_conf_label(mod_items_conf, item->item_name)) == NULL)
			{
				sync_cli_free_conf_file(&mod_items_conf);
				item = item->item_next;
				continue;
			}

			if (sync_cli_deal_item_value(mod_item_label_name, "null") == false)
			{
				return false;
			}
		}

		item = item->item_next;
	}

	return true;
}

#if 0
void dis_args(char **args)
{
	int i = 0;
	while (args[i] != NULL)
	{
		printf("文件同步输出参数列表分别为：[%d]: %s\n", i, args[i]);
		++i;
	}
}
#endif

int sync_cli_deal_item_value(sync_conf_labels_t *que, char *item_name)
{
	puts("----------------------11");
	int i = 0;
	char **args = NULL;

	sync_conf_items_t *item = NULL;
	sync_conf_items_t *tmp = NULL;

	if ((que == NULL) || (item_name == NULL))
	{
		return true;
	}

	tmp = que->label_item;
	while (tmp != NULL)
	{
		++i;
		tmp = tmp->item_next;
	}

	args = (char**)malloc(sizeof(void*)*(i+1));
	args[i] = NULL;

	i = 0;
	item = que->label_item;
	while (item != NULL)
	{
		args[i++] = item->item_value;
		item = item->item_next;
	}
	if (sync_cli_start_parse_file(i, args) == false)
	{
		free(args);
		return false;
	}

	free(args);
	return true;
}

size_t sync_cli_get_file_size(FILE *fp)
{
	if(fp == NULL)
	{
		return 0;
	}

	struct stat fs;
	fstat(fp->_fileno, &fs);

	return fs.st_size;
}


int sync_cli_pkg_single_file(char* file_name)
{
	int i;
	//int fname_len = 0;
	int fdata_len = 0;

	//int proto_len = 0;
	int cur_len = 0;
	int tmp_len = 0;

	int send_len = 0;
	char rec_buf[1024] = {0};
	char file_md5[64] = {0};

	char *p_send_buf = NULL;
	char *p_data_buf = NULL;
	//unsigned char *p_data_md5 = NULL;

	FILE *fp = NULL;
	size_t fsize = 0;

	MD5_CTX mdContext;
	sync_cli_md5_init (&mdContext);

	printf("filename:%s\n", file_name);
	if ((fp = fopen(file_name, "r")) == NULL)
	{  
		//printf("文件同步文件:\t%s 无法打开读写！\n", file_name);  
		dmanage_log_err(PRE_HAWK_LOG "act=\"%s\" msg=\"%s\" filename=\"%s\" " , 
				SYNC_MOD_NAME, SYNC_LOGERR_FILE_CANT_READ, file_name);

		return false;  
	}  

	fsize = sync_cli_get_file_size(fp);
	fdata_len = (int)fsize;
	//fname_len = strlen(file_name);
	send_len = sizeof(sync_pkg_head_t) + fdata_len;		
	p_send_buf = (char*)malloc(send_len);
	p_data_buf = p_send_buf + sizeof(sync_pkg_head_t);

	while ((tmp_len = fread(rec_buf, sizeof(char), BUFFER_SIZE, fp)) > 0)
	{
		memcpy( p_data_buf + cur_len, rec_buf, tmp_len);
		cur_len = cur_len + tmp_len;	
	}

	sync_cli_md5_update (&mdContext, (unsigned char*)p_data_buf, fdata_len);
	sync_cli_md5_final (&mdContext);

	for(i=0; i<16; i++)
	{
		sprintf(&file_md5[i*2], "%02x", mdContext.digest[i]);
		printf("ptrmd5: %p, i: %d, send_len: %d\n", &file_md5[i*2], i, send_len);
	}

	sync_pkg_head_t *pkg_head = (sync_pkg_head_t *)p_send_buf;
	memcpy(pkg_head->sync_pkg_head_flg, SYNC_PKG_HEAD_FLG, strlen(SYNC_PKG_HEAD_FLG));
	pkg_head->sync_pkg_file_name_len = strlen(file_name);
	pkg_head->sync_pkg_file_cont_len = fdata_len;
	memcpy(pkg_head->sync_pkg_file_name, file_name, strlen(file_name));
	memcpy(pkg_head->sync_pkg_file_md5, file_md5, 32);

	t_disbuf(p_send_buf, send_len);
	
	if (sync_cli_send_file_data(file_name, p_send_buf, send_len) == false)
		return false;

	free(p_send_buf);
	fclose(fp);

	return true;
}


int sync_cli_init_sock(unsigned int s_ip, unsigned short s_port)
{
	int server_socket = 0;
	struct sockaddr_in   server_addr;  

	memset(&server_addr, 0x00, sizeof(server_addr));  
	socklen_t server_addr_length = sizeof(server_addr);  

	server_addr.sin_family = AF_INET;  
	server_addr.sin_addr.s_addr = htonl(s_ip);  
	server_addr.sin_port = htons(s_port);  

	server_socket = socket(PF_INET, SOCK_STREAM, 0);  
	if (server_socket < 0)  
	{  
		dmanage_log_err(PRE_HAWK_LOG "act=\"%s\" msg=\"%s\" " , 
				SYNC_MOD_NAME, SYNC_LOGERR_SOCK_INIT);

		//printf("文件同步初始化套接字失败！\n");
		return false;
	}  

	if (connect(server_socket, (struct sockaddr*)&server_addr, server_addr_length) < 0)  
	{  
		dmanage_log_err(PRE_HAWK_LOG "act=\"%s\" msg=\"%s\" " , 
				SYNC_MOD_NAME, SYNC_LOGERR_SOCK_CONN);

		//printf("文件同步无法进行网络连接！\n");
		return false;
	}  

	return server_socket;
}

int sync_cli_read_sock_conf()
{
	char *val = NULL;

	sync_conf_labels_t *general = NULL;
	sync_conf_labels_t *conf = NULL;

	if ((conf = sync_cli_load_conf_file(sync_sock_conf_path)) == NULL)
	{
		//printf("加载配置文件同步网络配置文件失败!\n");
		dmanage_log_err(PRE_HAWK_LOG "act=\"%s\" msg=\"%s\" confname=\"%s\"" , 
				SYNC_MOD_NAME, SYNC_LOGERR_SOCK_LOAD_LABEL, sync_sock_conf_path);

		return false;
	}

	if ((general = sync_cli_load_conf_label(conf, sync_sock_conf_label)) == NULL)
	{
		//printf("加载配置文件同步网络配置文件标签项失败!\n");
		dmanage_log_err(PRE_HAWK_LOG "act=\"%s\" msg=\"%s\" labelname=\"%s\"" , 
				SYNC_MOD_NAME, SYNC_LOGERR_SOCK_READ_LABEL, sync_sock_conf_label);

		sync_cli_free_conf_file(&conf);
		return false;
	}

	if ((val = sync_cli_get_label_value(general, sync_sock_conf_ip)) != NULL)
	{
		printf("ip:%s\n", val);
		sync_sock_addr.s_ip = sync_cli_trans_inet_atoul(val);
	}

	if ((val = sync_cli_get_label_value(general, sync_sock_conf_port)) != NULL)
	{
		printf("port:%s\n", val);
		sync_sock_addr.s_port = (unsigned short)atoi(val);
	}

	sync_cli_free_conf_file(&conf);

	return true;
}

int sync_cli_send_file_data(char *file_name, char *send_buf, int send_len)
{

	int n = 0;
	int s_socket = 0;
	int tmp = 0;

	if (sync_cli_read_sock_conf() == false)
	{
		return false;
	}

	puts("-------------------------22");	
	s_socket = sync_cli_init_sock(sync_sock_addr.s_ip, sync_sock_addr.s_port);
	if (s_socket == false) 
	{
		//printf("文件同步读取网络连接失败\n");
		return false;
	}

	while (n != send_len)
	{
		tmp = send(s_socket, send_buf, send_len, 0);
		printf("tmp:%d\n", tmp);
		if (tmp < 0)
		{
			//printf("文件同步发送数据失败\n");
			dmanage_log_err(PRE_HAWK_LOG "act=\"%s\" msg=\"%s\" " , 
					SYNC_MOD_NAME, SYNC_LOGERR_SOCK_SEND);
			return false;
		}
		else
		{
			n = n + tmp;
		}
	}

	dmanage_log_notice(PRE_HAWK_LOG "act=\"%s\" msg=\"%s\" filename=\"%s\"" , 
			SYNC_MOD_NAME, SYNC_LOGNT_FINISH_SEND, file_name);

	close(s_socket);
	return true;
}

int sync_cli_start_parse_file(int argc, char **argv)
{
	int i=0;
	for ( i = 0; i < argc; i++)
	{
		printf("%s\n", argv[i]);
		if (sync_cli_pkg_single_file(argv[i]) == false)
		{
			//printf("文件同步处理文件 %s 失败!\n", argv[i]);
			dmanage_log_notice(PRE_HAWK_LOG "act=\"%s\" msg=\"%s\" filename=\"%s\"" , 
					SYNC_MOD_NAME, SYNC_LOGERR_FILE_DEAL, argv[i]);
			continue;
		}
	}		

	return true;
}

int main(int argc, char **argv)
{
	sync_conf_labels_t *general = NULL;
	sync_conf_labels_t *mod_option_conf = NULL;

	if ((mod_option_conf = sync_cli_load_conf_file(sync_mod_conf_path)) == NULL)
	{
		//printf("%s\n", "文件同步加载配置文件错误!");
		dmanage_log_err(PRE_HAWK_LOG "act=\"%s\" msg=\"%s\" confname=\"%s\"" , 
				SYNC_MOD_NAME, SYNC_LOGERR_LOAD_LABEL, sync_mod_conf_path);

		return false;
	}

	if ((general = sync_cli_load_conf_label(mod_option_conf, 
					sync_mod_conf_label)) == NULL)
	{
		//printf("%s\n","文件同步读取配置文件错误");
		dmanage_log_err(PRE_HAWK_LOG "act=\"%s\" msg=\"%s\" labelname=\"%s\"" , 
				SYNC_MOD_NAME, SYNC_LOGERR_READ_LABEL, sync_mod_conf_label);

		sync_cli_free_conf_file(&mod_option_conf);
		return false;
	}

	dmanage_log_notice(PRE_HAWK_LOG "act=\"%s\" msg=\"%s\"", 
			SYNC_MOD_NAME, SYNC_LOGNT_START_CLI);

	if (sync_cli_deal_label_value(general, "null") ==  false)
	{
		printf("%s\n", "文件同步配置失败");
	}
	else
	{
		printf("%s\n", "文件同步配置成功");
	}

	sync_cli_free_conf_file(&mod_option_conf);

	return true;
}
