#ifndef __CONFIGURATION_H_
#define __CONFIGURATION_H_

#include "sysheader.h"

typedef uint64_t	u64;
typedef uint32_t	u32;
typedef uint16_t	u16;
typedef uint8_t		u8;
typedef unsigned char u_char;
typedef long int      l_int;
typedef unsigned long int ul_int;

#define				MTP_VERSION_STR	"Topmtp-v1.4.1"
#define				MTP_VERSION		0x0140
#define  BUF_SIZE        1024*8

#define SA                   struct sockaddr
#define SAI                  struct sockaddr_in

#define DO_EXIT              0x00
#define DO_REQST             0x00
#define DO_REPLY             0x01
#define DO_CLOSE             0x02
#define DO_QUIT              0x03
#define DO_INIT              0x04

#define REPLACE_ONE          1
#define REPLACE_ALL          -1

#define PROXY_AUTH_SERVER    0x00
#define PROXY_VIDEO_SERVER   0x01
#define FILTER_USER          0x00
#define FILTER_GLOBAL        0x01

#define MAX_ARRAY            64
#define FTP_PORT             21

#define MAXFD                0x64
#define MAXEPOLLSIZE         1000
#define EPOLLWAITTIME        5000
#define FD_MAXSIZE           65535

#define FILE_MODE            0755
#define FR_SMNAME            "vp_fiber"
#define MA_SMNAME            "vp_megaeyes"        /* share mem and video stream process */

#define P_TCP_PROXY          0x00
#define P_UDP_PROXY          0x01
#define V_UDP_PROXY          "vp-vsudp"
#define V_TCP_PROXY          "vp-vstcp"

#define PRO_PID_PATH         "/var/run"
#define DEFAULT_APP_DIR      "/topapp/topvp"
#define GENERAL_CONFIG_FILE  "/topconf/topvp/general.conf"
#define PLATFORM_CONFIG_DIR  "/topconf/topvp/platforms"
#define SYS_CONFIG_FILE      "/topconf/topvp/system.conf"

#define DB_PATH              "/topapp/webapp/VPSer/WEB-INF"
#define DB_NAME              "vgap_pf"
#define SYS_LI_NAME          "sys-license"

#define SZ_CFGVAL   32
enum m_conf_value {
    L_AUTHIP,
    L_AUTHPORT,
    D_AUTHIP,
    D_AUTHPORT,
    V_PEERIP,
    S_TIMEOUT,
    L_VIDEOIP,
    L_VIDEOPORT,
    D_VIDEOIP,
    D_VIDEOPORT,
    C_TOTAL
};

enum m_conf_info
{
    L_ETH0_IP,  // local ip
    L_ETH1_IP,
    P_ETH0_IP,  // peer ip
    P_ETH1_IP,
    S_IP,       // source ip
    D_IP,       // dest ip
    I_TOTAL,
};

struct general_config_t
{
    int  is_loaded;
    int  host_side;          // current hosts side(inner/outer)

#define HOST_SIDE_INNER 0x01
#define HOST_SIDE_OUTER 0x02

    u32  inner_addr;        // innet public ip
    u32  outer_addr;        // outnet public ip
    u32  inner_priv_addr;
    u32  outer_priv_addr;
    u32  local_priv_addr;
    u32  peer_priv_addr;

    u16  ferry_port;
    u16  sysmana_port;
    char *app_dir;
    int sz_buffer;
};

typedef struct __conf_item
{
    char *item_name;
    char *item_value;
    struct __conf_item *item_next;
} conf_item;

typedef struct __query_conf
{
    char *label_name;
    conf_item *label_item;
    struct __query_conf *label_next;
} query_conf;

typedef struct __frame_modify_paras
{
    bool frame_enable;
    int frame_modify_flg;
    int frame_modify_num;
} frame_modify_paras;

bool init_frame_paras();
int frame_run_count(int * count);
char *pre_deal_with_line(char *line);

query_conf *load_configuration(const char *filepath);
void free_configuration(query_conf **pque);
char *get_conf_value(char *label_name, char *item_name, query_conf *p_query_conf);

query_conf *find_label(query_conf *p_query_conf, char *label_name);
char *get_value_from_label(query_conf *que, char *item_name);
int __load_general_config();
int __load_general_config_path(const char *path);


extern frame_modify_paras g_frmp; 
extern char m_conf_key[][32];
extern struct general_config_t g_general_config;
#define __gg  g_general_config


#endif	// __CONFIGURATION_H_	

