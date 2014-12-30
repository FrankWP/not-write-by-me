#ifndef _COMMON_28181_H_
#define _COMMON_28181_H_

#include "../vpheader.h"

bool sip_is(const char *pkg, const char *type);
int get_cmd_ip_port(char *pkg, u32 len_pkg, char *ip, char *port);
char *get_call_id(char *pkg, u32 len_pkg, char *call_id, u32 sz_call_id);
int replace_cmd_ip_port(char **pkg, u32 *len_pkg, char *ip_to, u16 port_to);
int do_sip_reply_replace_to_by_key(pvp_uthttp put, const char *key, const char *dst_ip, u16 dst_port, char **ut_buf, u32 *pack_len);
int replace_received(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int replace_via(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int replace_via_hik_register(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int replace_rport_received(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int do_sip_replace_invite(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int do_ferry_sip_request_register(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int do_ferry_sip_request_message(pvp_uthttp put, char **ut_buf, u32 *pack_len);
int replace_key_of_from(char **ut_buf, u32 *pack_len, char *ip_to, u16 port_to);

#endif  // _COMMON_28181_H_

