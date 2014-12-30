#ifndef __VP_UTHTTP_H
#define __VP_UTHTTP_H

#include "common.h"
#include "vp_thread_setting.h"
#include "visit_list.h"

#define  T_RUNNING       0x00
#define  T_WAITING       0x01
#define  T_DETACH        0x02
#define  N_CACHE         0x00
#define  Y_CACHE         0x01

#define  SIP_MAX_SIZE    1024*1024*64

#define  HTTP_LINE_END   "\r\n"
#define  HTTP_HEAD_END   "\r\n\r\n"
#define  HTTP_CHUNK_END  "\r\n0\r\n\r\n"
#define  HTTP_CHUNK_END2  "\r\n0000\r\n\r\n"
#define  CONTENT_LENGTH  "Content-Length"
#define  HTTP_CHUNK_CHK  "Transfer-Encoding: chunked"

typedef struct VP_UTHTTP {
    u32  lip;               // local listen ip
    u16  lport;             // local listen port
    u32  dip;               // visit des ip
    u16  dport;             // visit des port
    u16  session_tout;      // session visit time out
    u32  platform_id;       // the platform id of mark different video services
	char login_user[64];
    char req_cmd[64];       // request commond
    int  changeable;        // the value use at the different platform
    u32  peerip;            // tms or ums ip
    int  data_cache;        // recv data mode
    th_set tset;

    u32  bind_video_ip;   // the ip need to bind port
    u16  bind_video_port; // bind port for tms or ums 
    u32  src_ip;
    u16  src_port;
    int  cli_sock;
    int  svr_sock;
    SAI  cli_addr;
    SAI  svr_addr;
} *pvp_uthttp, vp_uthttp;

typedef struct VP_UTHTTP_TRANS
{
    vp_uthttp vphttp;

    int  (* do_socket)(pvp_uthttp put, int sockfd);
    int  (* do_close)(pvp_uthttp put, int sockfd);
    int  (* do_recv)(pvp_uthttp put, char *buf, int *pack_len, int direct);
    int  (* do_request)(pvp_uthttp phttp, char **buf, u32 *pack_len);
    int  (* do_reply)(pvp_uthttp phttp, char **buf, u32 *pack_len);
}*pvp_uthtrans, vp_uthtrans;

typedef struct vp_ferry_req
{
    u32 cip;    // inner client ip
    u32 lip;    // local ip (ums ip)
    u32 dip;    // destination ip (outer server ip)
    u16 lport;
    u16 cport;
    u16 dport;
    u16 ipproto;
    u32 sesn_timeout;
} vp_ferry_req_t;

typedef struct vp_ferry_tcp_req
{
    u32  sip;
    u32  dip;
    u16  sport;
    u16  dport;
    u16  ipproto;
    u16  ctofy;// received from client by ferry
    u16  stofy;// received from server by ferry
    u32  bind_video_ip;   // the ip need to bind port
    u16  bind_video_port; // bind port for tms or ums 
} vp_ferry_tcp_req_t;

typedef struct vp_ferry_udp_req
{
    u32 sip;
    u32 dip;
    u16 sport;
    u16 dport;
    u16 sesn_timeout;
    u32  bind_video_ip;   // the ip need to bind port
    u16  bind_video_port; // bind port for tms or ums 
} vp_ferry_udp_req_t;

/*
   typedef struct vp_ferry_udp_reply
   {
   int status;
   int x_errno;
   } vp_ferry_udp_reply_t;
   */

typedef struct __vp_ippool_head {
    u32 ip;
    int x_errno;
} vp_ippool_head;

typedef void*(*tfunc_runproxy)(void*);

int  http_parse_req_head(u32 *hlen, u32 *blen, char *dbuf);
int  http_parse_req_data(char **reqst, char *dbuf, int ret, u32 *dtotal, u32 *hlen, u32 *blen);
int  http_general_mode(char **reqst, char *buf, int ret, u32 *tl, u32 *hl, u32 *bl);

int  http_chunked_check(char *str, u32 len);
int  http_chunked_change(char *str, u32 *rt);
int  http_chunked_deal(char **reqst, char *buf, u32 *total, int ret, int chunked);
int  http_chunked_content(char *str);
int  http_chunked_exchange(char * str, u32 lbody, u32 *total);
int  http_chunked_mode(char **reqst, char *buf, int ret, u32 *tl, int *chk);

int  ut_parse_req_data(char **reqst, char *dbuf, int ret, u32 *dtotal);

int  __load_general_config();
int  x_sendto_xy(int sockfd, char *buf, int len, int flags,struct sockaddr *src, 
     //   struct sockaddr *to, socklen_t tolen,  pvp_uthtrans puh);
          struct sockaddr *to, socklen_t tolen, vp_uthttp *pvp_arg);

//int  tcp_accept(int lsn_sock, SAI *cliaddr, u32 *sip, u16 *sport, u32 *dip, u16 *dport);
//int  tcp_accept(int lsn_sock, SAI *cliaddr, u32 *sip, u16 *sport, u32 *dip, u16 *dport, th_set *tset);
int tcp_accept(int lsn_sock, SAI *cliaddr, pvp_uthtrans puthtrans);
//int  tcp_connect(u32 sip, u16 sport, u32 dip, u16 dport, int sersock, int tm_out);
//int  tcp_connect(u32 sip, u16 sport, u32 dip, u16 dport, th_set *tset,  int sersock, int tm_out);
int tcp_connect(int sersock, int tm_out, pvp_uthtrans puthrans);

int  load_tcp_proxy_simple_s(int t_state, int pmid, const char *tout, const char *peer_ip,
        const char *lip, const char *lport, const char *dip, const char *dport,
        int (* do_socket)(pvp_uthttp put, int sockfd),
	    int (* do_recv)(pvp_uthttp put, char *buf, int *pack_len, int direction),
        int (* do_request)(pvp_uthttp phttp, char **buf, u32 * pack_len),
        int (* do_reply)(pvp_uthttp phttp, char **buf, u32 * pack_len),
        int (* do_close)(pvp_uthttp put, int sockfd));
int  load_udp_proxy_simple_s(int t_state, int pmid, const char *tout, const char *peer_ip,
        const char *lip, const char *lport, const char *dip, const char *dport,
        int (* do_socket)(pvp_uthttp put, int sockfd),
	    int (* do_recv)(pvp_uthttp put, char *buf, int *pack_len, int direction),
        int (* do_request)(pvp_uthttp phttp, char **buf, u32 * pack_len),
        int (* do_reply)(pvp_uthttp phttp, char **buf, u32 * pack_len),
        int (* do_close)(pvp_uthttp put, int sockfd));
int  load_tcp_proxy_simple_n(int t_state, int pmid, int tout, u32 peer_ip,
        u32 lip, u16 lport, u32 dip, u16 dport,
        int (* do_socket)(pvp_uthttp put, int sockfd),
	    int (* do_recv)(pvp_uthttp put, char *buf, int *pack_len, int direction),
        int (* do_request)(pvp_uthttp phttp, char **buf, u32 * pack_len),
        int (* do_reply)(pvp_uthttp phttp, char **buf, u32 * pack_len),
        int (* do_close)(pvp_uthttp put, int sockfd));
int  load_udp_proxy_simple_n(int t_state, int pmid, int tout, u32 peer_ip,
        u32 lip, u16 lport, u32 dip, u16 dport,
        int (* do_socket)(pvp_uthttp put, int sockfd),
	    int (* do_recv)(pvp_uthttp put, char *buf, int *pack_len, int direction),
        int (* do_request)(pvp_uthttp phttp, char **buf, u32 * pack_len),
        int (* do_reply)(pvp_uthttp phttp, char **buf, u32 * pack_len),
        int (* do_close)(pvp_uthttp put, int sockfd));
 
int  load_tcp_proxy(pvp_uthtrans pt, int t_state);
int  load_ferry_tcp_proxy(pvp_uthtrans pt, int t_state);
int  load_udp_proxy(pvp_uthtrans pu, int t_state);
int  load_ferry_udp_proxy(pvp_uthtrans pu, int t_state);

void set_trans_arg(vp_uthtrans *ptrans, int pmid, int tout, u32 peer_ip,
		u32 lip, u16 lport,
		u32 dip, u16 dport,
        int (* do_socket)(pvp_uthttp put, int sockfd),
	    int (* do_recv)(pvp_uthttp put, char *buf, int *pack_len, int direction),
        int (* do_request)(pvp_uthttp phttp, char **buf, u32 * pack_len),
        int (* do_reply)(pvp_uthttp phttp, char **buf, u32 * pack_len),
        int (* do_close)(pvp_uthttp put, int sockfd));

int __start_vs_proxy(clivlist *pcvn, const char *vs_type, u16 priv_port, bool use_pp);
int __start_vs_tcp_proxy(clivlist *pcvn, bool flags, u16 priv_port);
int __start_vs_udp_proxy(clivlist *pcvn, bool flags, u16 priv_port);
int run_vs_proxy(const char *type, u32 lip, u32 dip, u16 lport, u16 dport, int pmid, int tout, int ferry_port);
int run_vs_udp_proxy(u32 lip, u32 dip, u16 lport, u16 dport, int pmid, int tout, int ferry_port);
int run_vs_tcp_proxy(u32 lip, u32 dip, u16 lport, u16 dport, int pmid, int tout, int ferry_port);
int run_thread_udp_proxy(u32 lip, u32 dip, u16 lport, u16 dport, int tout);
int run_thread_tcp_proxy(u32 lip, u32 dip, u16 lport, u16 dport, int tout);
int run_thread_tout_udp_proxy(u32 lip, u32 dip, u16 lport, u16 dport, int tout, bool tout_exit, bool port_free);
int run_thread_tout_tcp_proxy(u32 lip, u32 dip, u16 lport, u16 dport, int tout, bool tout_exit, bool port_free);
// for sip protocol use
int replace_sip_contact(char **ppbuf, u32 *pbuf_len, char *ip_from, char *ip_to, int port_from, int port_to);

#endif // ~__VP_UTHTTP_H_
