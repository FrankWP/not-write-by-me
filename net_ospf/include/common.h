#ifndef _COMMON_H_
#define _COMMON_H_

#include <pcap.h>   
#include <stdlib.h>   
#include <stdio.h>   
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/ip.h>
//#include <linux/udp.h>
#include <net/if.h>
#include <strings.h>

#define SUCCESS         (0)
#define FAILURE         (-1)
#define OUTSIDE         "outside"
#define INSIDE          "inside"

typedef unsigned char        U8;
typedef unsigned short       U16;
typedef unsigned int         U32;
typedef unsigned long long   U64;

typedef char      S8;
typedef short     S16;
typedef int       S32;
typedef long long S64;

/* max length of packet */
#define MAX_PKT_SIZE    (65535)

/* length of interface name */
#define SIZE_NAME       (32)

/* Common options */
#define CFG_COM_TASK    "[ common ]"

/* receive options */
#define CFG_RT_TASK	    "[ router ]"

/* configure file */
#define CFG_FILE        "./config/net_ospf.conf"

/* Host name */
#define INSIDE			"inside"
#define OUTSIDE			"outside"

/* program id file */
#define PID_FILE		"/var/run/net_ospf.pid"

/* 224.0.0.5 */
#define ALLSPFRouters (0x050000e0)

/* 224.0.0.6 */
#define ALLDRouters (0x060000e0)

/* Define debug printf */
#ifdef LOG_NOTICE
    #define LOGN(fmt, args...) \
    do{ \
	    printf("\033[40;37m[NOTICE] \033[0m"); \
        printf(fmt, ##args); \
    }while (0);
#else
    #define LOGN(fmt, ...)
#endif

#ifdef LOG_DEBUG
    #define LOGD(fmt, args...) \
    do{ \
        printf("\033[40;35m[DEBUG][%-4d] \033[0m", __LINE__); \
	    printf(fmt, ##args); \
    }while (0);
#else
    #define LOGD(fmt, ...)
#endif

#ifdef LOG_WARNING
    #define LOGW(fmt, args...) \
    do{ \
        printf("\033[40;32m[WARNING][%s:%-4d] \033[0m", __FUNCTION__, __LINE__); \
        printf(fmt, ##args); \
    }while (0);
#else
    #define LOGW(fmt,...)
#endif


#ifdef LOG_ERROR 
    #define LOGE(fmt, args...) \
    do{ \
        printf("\033[40;31m[ERROR][%s:%-4d][%s] \033[1m", __FUNCTION__, __LINE__, strerror(errno)); \
        printf(fmt, ##args); \
    }while (0);
#else
    #define LOGE(fmt,...)
#endif

/*******************
 *   Functions     *
 *******************/
int x_getpid(const char *pid);
int x_writepid(const char *pid);
int ip_aton(char *sip);
char *ip_ntoa(int sip, char *rvip);
int daemon_init();
unsigned short csum(unsigned short *buffer, int size);
int init_rawsock(int protocol);
void output_hex(unsigned char *buff, int len);
void ip_net_display(void *paddr);
void ip_host_display(void *paddr);

#endif // _COMMON_H_
