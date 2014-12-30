#ifndef  __PM_PROXY_H
#define  __PM_PROXY_H

#include "../vpheader.h"
#include "common_28181.h"
#include "common_keda.h"

struct pm_proxy
{
//    enum __e_head_type head_type;
    int pm_id;
    int proxy_type;
    int time_out;
    u32 lip;
    u16 lport;

    char  *manu;
    void (* pm_quit)();
    int  (* do_socket)(pvp_uthttp put, int sockfd);
    int  (* do_recv)(pvp_uthttp put, char *data_buf, int *data_len, int direction);
    int  (* do_request)(pvp_uthttp put, char **ut_buf, u32 *pack_len);
    int  (* do_reply)(pvp_uthttp put, char **ut_buf, u32 *pack_len);
    int  (* do_close)(pvp_uthttp put, int sockfd);
};

extern struct pm_proxy g_pm;

bool pm_init(struct pm_proxy *pm, const char *arg);
//bool pm_init(int proxy_type, int time_out, const char *manu);
void pm_quit();

int __start_media_proxy(char *type, u32 lip, u32 dip, u16 lport, u16 dport, u16 tout, int priv_port);
int do_sip_ok(pvp_uthttp put, char **ut_buf, u32 *pack_len, int direction);
bool is_tms();

#define FERRY_MANU_AMPLESKY "amplesky"
int  __amplesky_init();
void __amplesky_quit();
int  __amplesky_request(pvp_uthttp put, char **ut_buf, u32 *pack_len);
void __amplesky_replace_allproto_uplen(char **ut_buf, u32 *pack_len, char *src, char *dst);

#define FERRY_MANU_AMPLESKY28181    "amplesky-v28181"
int  __amplesky28181_init(const char *parg);
void __amplesky28181_quit();
int  __amplesky28181_socket(pvp_uthttp put, int sockfd);
int  __amplesky28181_request(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int  __amplesky28181_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int  __amplesky28181_close(pvp_uthttp put, int sockfd);
int do_sip_reply_invite(pvp_uthttp put, char **ut_buf, u32 *pack_len);
/*
int get_cmd_ip_port(char *pkg, u32 len_pkg, char *ip, char *port);
int replace_cmd_ip_port(char **pkg, u32 *len_pkg, char *ip_to, u16 port_to);
int do_sip_reply_replace_to_by_key(pvp_uthttp put, const char *key, const char *dst_ip, u16 dst_port, char **ut_buf, u32 *pack_len);
int replace_via(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int replace_received(pvp_uthttp put, char **ut_buf, u32 *pack_len);
char *get_call_id(char *pkg, u32 len_pkg, char *call_id, u32 sz_call_id);
*/

#define FERRY_MANU_HIK28181    "hik-v28181"
int  __hik28181_init(const char *parg);
void __hik28181_quit();
int  __hik28181_socket(pvp_uthttp put, int sockfd);
int  __hik28181_request(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int  __hik28181_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int  __hik28181_close(pvp_uthttp put, int sockfd);

#define FERRY_MANU_KEDA2800 "keda-v2800"
int  __keda2800_init(const char *parg);
void __keda2800_quit();
int  __keda2800_socket(pvp_uthttp put, int sockfd);
int  __keda2800_recv(pvp_uthttp put, char *ut_buf, int *pack_len, int direction);
int  __keda2800_request(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int  __keda2800_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int  __keda2800_close(pvp_uthttp put, int sockfd);

#define FERRY_MANU_KEDA2801E "keda-v2801e"
int  __keda2801e_init(const char *parg);
//int  __keda2801e_socket(pvp_uthttp put, int sockfd);
int  __keda2800_request(pvp_uthttp put, char **ut_buf, u32 *pack_len);
void __keda2801e_quit();

#define FERRY_MANU_SANDUN "sandun"
int  __sandun_init();
void __sandun_quit();
int  __sandun_request(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int  __sandun_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int  __sandun_close(pvp_uthttp put, int sockfd);

#define FERRY_MANU_HUASAN "huasan"
int  __huasan_init();
void __huasan_quit();
int  __huasan_socket(pvp_uthttp put, int sockfd);
int  __huasan_request(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int  __huasan_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int  __huasan_close(pvp_uthttp put, int sockfd);

#define FERRY_MANU_H3C_V8500 "h3c-v8500"
int  __h3c_v8500_init();
void __h3c_v8500_quit();
int  __h3c_v8500_socket(pvp_uthttp put, int sockfd);
int  __h3c_v8500_close(pvp_uthttp put, int sockfd);
int  __h3c_v8500_recv(pvp_uthttp put, char *ut_buf, int *pack_len, int direction);
int  __h3c_v8500_request(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int  __h3c_v8500_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len);

#define FERRY_MANU_JCH3C "jincheng-h3c"
int  __h3c_v8500_init();
void __h3c_v8500_quit();
int  __h3c_v8500_socket(pvp_uthttp put, int sockfd);
int  __h3c_v8500_recv(pvp_uthttp put, char *utbuf, int *pack_len, int directon);
int  __h3c_v8500_request(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int  __h3c_v8500_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int  __h3c_v8500_close(pvp_uthttp put, int sockfd);

#define FERRY_MANU_H3C "H3C"
#if 0
int  h3c_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len);
#endif
int  h3c_init();
void h3c_quit();
int  h3c_socket(pvp_uthttp put, int sockfd);
int  h3c_close(pvp_uthttp put, int sockfd);
int  h3c_recv(pvp_uthttp put, char *ut_buf, int *pack_len, int direction);
int  h3c_request(pvp_uthttp put, char **ut_buf, u32 *pack_len);

#define FERRY_MANU_DATANG "datang"
int  __datang_init();
void __datang_quit();
int  __datang_socket(pvp_uthttp put, int sockfd);
int  __datang_close(pvp_uthttp put, int sockfd);
//int  __datang_recv(pvp_uthttp put, char *ut_buf, int *pack_len, int direction);
int  __datang_request(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int  __datang_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int start_datang_proxy(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int start_datang_media_proxy(pvp_uthttp put, char **ut_buf, u32 *pack_len, u32 lip, u32 dip, int tout);

#define FERRY_MANU_DAHUA "dahua"
int  __dahua_init();
void __dahua_quit();
int  __dahua_socket(pvp_uthttp put, int sockfd);
int  __dahua_recv(pvp_uthttp put, char *ut_buf, int *pack_len, int direction);
int  __dahua_request(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int  __dahua_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int  __dahua_close(pvp_uthttp put, int sockfd);

#define FERRY_MANU_ZSYH "zsyh"
int  __zsyh_init();
void __zsyh_quit();
int  __zsyh_socket(pvp_uthttp put, int sockfd);
int  __zsyh_recv(pvp_uthttp put, char *ut_buf, int *pack_len, int direction);
int  __zsyh_request(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int  __zsyh_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int  __zsyh_close(pvp_uthttp put, int sockfd);

#define FERRY_MANU_HARERBIN_KEDA_CHENGGUAN "haerbin-keda-chengguan"
int __keda_haerbin_chengguan_init();
void __keda_haerbin_chengguan_quit();
int __keda_haerbin_chengguan_recv(pvp_uthttp put, char *ut_buf, int *pack_len, int direction);
int __keda_haerbin_chengguan_socket(pvp_uthttp put, int sockfd);
int __keda_haerbin_chengguan_request(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int __keda_haerbin_chengguan_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int __keda_haerbin_chengguan_close(pvp_uthttp put, int sockfd);

#define FERRY_MANU_H3C_FS "H3C_FS"
int  h3c_fs_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int  h3c_fs_init();
void h3c_fs_quit();
int  h3c_fs_socket(pvp_uthttp put, int sockfd);
int  h3c_fs_close(pvp_uthttp put, int sockfd);
int  h3c_fs_recv(pvp_uthttp put, char *ut_buf, int *pack_len, int direction);
int  h3c_fs_request(pvp_uthttp put, char **ut_buf, u32 *pack_len);

#define FERRY_MANU_H3C_HARBIN "H3C_HARBIN"
int  h3c_harbin_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int  h3c_harbin_init();
void h3c_harbin_quit();
int  h3c_harbin_socket(pvp_uthttp put, int sockfd);
int  h3c_harbin_close(pvp_uthttp put, int sockfd);
int  h3c_harbin_recv(pvp_uthttp put, char *ut_buf, int *pack_len, int direction);
int  h3c_harbin_request(pvp_uthttp put, char **ut_buf, u32 *pack_len);

#define FERRY_MANU_TIANDIWEIYE  "tiandiweiye"
int __tiandiweiye_init(const char *parg);
void __tiandiweiye_quit();
int __tiandiweiye_recv(pvp_uthttp put, char *ut_buf, int *pack_len, int direction);
int __tiandiweiye_socket(pvp_uthttp put, int sockfd);
int __tiandiweiye_request(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int __tiandiweiye_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int __tiandiweiye_close(pvp_uthttp put, int sockfd);

#define FERRY_MENU_HIK "hik"
int hik_fcg_init();
void hik_fcg_quit();
int hik_fcg_request(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int hik_fcg_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len);

#define FERRY_SHANGXI_JONET "jonet"
int jonet_init(const char *parg);
void jonet_quit();
int jonet_recv(pvp_uthttp put, char *ut_buf, int *pack_len, int direction);
int jonet_socket(pvp_uthttp put, int sockfd);
int jonet_request(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int jonet_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int jonet_close(pvp_uthttp put, int sockfd);

#define FERRY_MANU_ZHONGXING "zhongxing"
int zhongxing_henan_init(const char *parg);
void zhongxing_henan_quit();
int zhongxing_socket(pvp_uthttp put, int sockfd);
int zhongxing_henan_request(pvp_uthttp put, char **ut_buf, u32 *pack_len);

#define FERRY_HENAN_ZHONGXING "zhongxing"

#define FERRY_MANU_FIBER "fiber"
int __fiber_init(const char *parg);
void __fiber_quit();
int __fiber_recv(pvp_uthttp put, char *ut_buf, int *pack_len, int direction);
int __fiber_socket(pvp_uthttp put, int sockfd);
int __fiber_request(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int __fiber_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int __fiber_close(pvp_uthttp put, int sockfd);

#endif // ~__PM_PROXY_H
