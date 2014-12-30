#ifndef  __COMMON_H
#define  __COMMON_H

#include "sysheader.h"
#include "udeftype.h"
#include "config.h"
#include "memreplace.h"

#define COUNTTOUT(x, y) ((x.tv_sec - y.tv_sec)*1000000 + \
        x.tv_usec - y.tv_usec)/1000000
#define TDSECONDS(x) (x.tv_sec * 1000000 + x.tv_usec)/1000000

#define ADDR_TO_IPPORT(addr, ip, port) do { \
    ip = ntohl(addr.sin_addr.s_addr); \
    port = (u16)(ntohs)(addr.sin_port); \
} while (0)

// macros about syslog
#define OPENLOG(name) \
    openlog(name, LOG_CONS|LOG_PID|LOG_PERROR, LOG_USER);

#define loginf_out(info) syslog(LOG_INFO, "%s [%s:%s:%d]", info, __FUNCTION__, __FILE__, __LINE__)
#define logwar_out(info) syslog(LOG_WARNING, "%s", info)
#define logerr_out(info) syslog(LOG_ERR, "%s", info)
#define logdbg_out(info) syslog(LOG_DEBUG, "%s [%s:%s:%d] %s", info, __FUNCTION__, __FILE__, __LINE__, strerror(errno))
#define loginf_fmt(fmt, args...) syslog(LOG_INFO, fmt, args)
#define logwar_fmt(fmt, args...) syslog(LOG_WARNING, fmt, args)
#define logerr_fmt(fmt, args...) syslog(LOG_ERR, fmt, args)
#define logdbg_fmt(fmt, args...) syslog(LOG_DEBUG, fmt, args)

int  Send(int s, const void * buf, u32 len, int flags);
ssize_t Recvn(int fd, char *vptr, size_t n);
int  Recv(int s, void * buf, u32 len, int flags);
int  recv_tail(int sockfd, int extlen, char **ut_buf, u32 *pack_len);
int  recv_until_close(int sockfd, char **ut_buf, u32 *pack_len);
int  recv_until_end_flag(int sockfd, const char *flg, int len_flg, char **ut_buf, u32 *pack_len);
int  recv_until_flag(int sockfd, const char *flg, int len_flg, char **ut_buf, u32 *pack_len);
int  Bind(int sockfd, struct sockaddr_in saddr, u32 socklen);
int  Connect(int sockfd, struct sockaddr *serv_addr, socklen_t addrlen, int tm_out);
int  Accept(int s, struct sockaddr *addr, socklen_t *addrlen);
int  Select(int nfds, fd_set * rfds, fd_set * wfds, fd_set * efds, struct timeval * tout);
u16 getsockport(int sockfd);
int  noblock_accept(int fd, SA * paddr, int addrlen, int time_out);
int  Setsockopt(int sock, int level, int optname);
void close_sock(int * sock);
void init_sockaddr(SAI * sockaddr, u32 ip, u16 port);
int  setnonblocking(int sockfd);
int  set_sock_timeout(int sockfd, int rTenthSec, int sTenthSec);
char * __strtrim(char * s);
char *trim(char *str);
char * trimleft(char *str);
char * trimright(char *str);
void getsubstring(char *str, char a[][MAX_ARRAY], char seg);
char *inet_ultoa(u32 u, char * s);
u32  inet_atoul(const char * s);
const char *set_app_dir(const char *app_dir);

int  strreply(char **content, char * src,
        char * dest, int replace_times, unsigned int * pack_len);
int  strreplace(char **content, char * src,
        char * dest, int replace_times, unsigned int * pack_len);
int  strreplace_pos(char *pos_b, char *pos_e, char **content, char *src, char *dst, int times, u32 *len);
int  memreplace_pos(char *pos_b, char *pos_e, char **content, u32 *len, int times, char *src, int nsrc, char *dst, int ndst);
char *strnstr(const char *haystack, const char *needle, int max_len, bool sensitive);
bool strncmp_sen(char *s1, char *s2, int max_len, bool sensitive);
int  vpprintf(const char * msg, ...); /* video platform output message */

int  __oss_malloc(void **p, int size); /* malloc memory, the ct for print model content */
void __oss_free(void **p);
//#define oss_free(ptr)   printf("%s:%d\n", __FILE__,__LINE__); __oss_free((void**)(ptr))
#define oss_free(ptr)   __oss_free((void**)(ptr))
#define oss_malloc(p, size) __oss_malloc((void**)(p), size)

int  Hex2Int(const char * str);
int get_content_len(char *buf, u32 len);
int get_content_len_http(char *buf, u32 len);
int get_content_len_osp(char *pkg,int start_pos);
void update_content_len(char **ut_buf, u32 *pack_len);
int  parse_key(char **ut_buf, char *key, char *seg);
int  set_webbrowser_nocache(char **reqst, int * pack_len);
void kill_process();
int  set_limit();

int  get_sharemem_pid();
int  start_vstream_proxy(char * proto_type, char * arg[]);
pid_t create_daemon();

long start_license(void(*before_exit)(int));
int  create_pid_file(const char * pid);
int  remove_pid_file(const char * pid);
int  load_proxy_config(const char *config_name,
        int pmid, int proxy_sign, char value[C_TOTAL][SZ_CFGVAL]);

int  __fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
int  __fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);

/*
 *   @ set a virtual cameraid when the platform services can not
 *   @ get real cameraid.
 *   @ if do not set the cameraid the vp-flow run failed.
 */
char * get_virtual_cameraid(char * cameraid);

/*
 *  @ user cert
 */
#define N_LOAD 0x00
#define Y_LOAD 0x01

bool load_user_cert();
bool test_user_cert(SAI cli_addr);
bool cert_is_enable();
int get_user_id(SAI cliaddr, char *userid);
int get_user_name(SAI cliaddr, char *username);

int find_sip_addr(char **ut_buf, char *ip, char *port);
void _t_disbuf(const unsigned char *buf, int len);
#define t_disbuf(p, size) _t_disbuf((const unsigned char*)(p), (int)size)
void _wlog(const char *name, char *str);
#define wlog(file, str) _wlog((const char*)(file), (char*)(str))
void _wlog2(const char *name, char *fmt, ...);
#define wlog2(file, fmt, args...) _wlog2((const char*)(file), (char*)(fmt), args)

u32 get_inet_ip_from_socket(int sockfd);
u16 get_inet_port_from_socket(int sockfd);

char *loop_line_from_buf(char *cursor, char *store, int storesz);
#endif  /* ~_COMMON_ */
