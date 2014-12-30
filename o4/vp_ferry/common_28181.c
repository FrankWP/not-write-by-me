#include "common_28181.h"

const static char SIP_FLAG_REGISTER[] = "REGISTER";
const static char SDP_SIGN[] = "application/sdp";
const static char SIP_FLAG_MESSAGE[] = "MESSAGE ";
const static char SIP_FLAG_OK[] = "SIP/2.0 200 OK";
const static char SIP_FLAG_INVITE[] = "INVITE ";
const static char SIP_FLAG_BYE[] = "BYE ";
const static char SIP_FLAG_ACK[] = "ACK ";
const static char SIP_FLAG_INFO[] = "INFO ";
const static char SIP_FLAG_CONTACT[] = "Contact:";
const static char SIP_FLAG_FROM[] = "From:";
const static char SIP_FLAG_TO[] = "To:";

bool sip_is(const char *pkg, const char *type)
{
    return (strncmp(pkg, type, strlen(type)) == 0);
}

int get_cmd_ip_port(char *pkg, u32 len_pkg, char *ip, char *port)
{
    if ((pkg == NULL) || (ip == NULL) || (port == NULL))
        return -1;

    char *ptr = NULL;
    char *ptr_cmd_end = NULL;
    if ((ptr_cmd_end = strnstr(pkg, "\r\n", len_pkg, true)) == NULL)
    {
        logdbg_out("get_cmd_ip_port: flag of end line \\r\\n not found!");
        return -1;
    }

    if ((ptr = strnstr(pkg, "@", ptr_cmd_end - pkg, true)) == NULL)
    {
        if ((ptr = strnstr(pkg, ":", ptr_cmd_end - pkg, true)) == NULL)
        {
            logdbg_out("get_cmd_ip_port: flag of ip not found!");
            return -1;
        }
        ptr += sizeof(':');
    }
    else
        ptr += sizeof('@');

    sscanf(ptr, "%[^:]", ip);
    ptr += strlen(ip) + sizeof(':');
    sscanf(ptr, "%[0-9]", port);

    return 1;
}

char *get_call_id(char *pkg, u32 len_pkg, char *call_id, u32 sz_call_id)
{
    // Call-ID: 3687028065@10.98.159.2:5060
    const static char FLG_CALLID[] = "Call-ID: ";
    char _call_id[128] = {0};

    if ((pkg == NULL) || (len_pkg == 0) || (call_id == NULL) || (sz_call_id == 0))
        return NULL;

    char *ptr = NULL;
    if ((ptr = (char*)memmem(pkg, len_pkg, FLG_CALLID, sizeof(FLG_CALLID)-1)) == NULL)
        return NULL;    // call id not found
    ptr += sizeof(FLG_CALLID)-1;
    sscanf(ptr, "%s[^\r\n]", _call_id);
    strncpy(call_id, _call_id, sz_call_id > sizeof(_call_id) ? sizeof(_call_id)-1:sz_call_id-1);
    printf("call id: %s\n", call_id);

    return call_id;
}

int replace_cmd_ip_port(char **pkg, u32 *len_pkg, char *ip_to, u16 port_to)
{
    char ip[16] = {0};
    char port[16] = {0};
    char r_src[64] = {0};
    char r_dst[64] = {0};

    if (get_cmd_ip_port(*pkg, *len_pkg, ip, port) < 0)
        return -1;
    sprintf(r_src, "%s:%s", ip, port);
    sprintf(r_dst, "%s:%d", ip_to, port_to);
    puts("replace ----- cmd ----- ip --------port ");
    printf("replace from:%s\n", r_src);
    printf("replace to:%s\n", r_dst);
    strreplace_pos(NULL,NULL, pkg, r_src, r_dst, 1, len_pkg);

    return 1;
}

int do_sip_reply_replace_to_by_key(pvp_uthttp put, const char *key, const char *dst_ip, u16 dst_port, char **ut_buf, u32 *pack_len)
{
    char src_ip[16] = {0};
    char src_port[16] = {0};
    //char *dst_ip = NULL;
    //u16 dst_port = 0;
    char *ptr = NULL;
    char *ptr_sip = NULL;
    char *ptr_sport = NULL;
    char cli_ip[16] = {0};
    char r_src[64] = {0};
    char r_dst[64] = {0};

    if ((ptr = strnstr(*ut_buf, key, *pack_len, false)) == NULL)
        return 1;
    ptr += strlen(key);
    if ((ptr_sip = strnstr(ptr, "@", *pack_len - (ptr - *ut_buf), true)) == NULL)
        return 1;
    else
        ptr_sip = ptr_sip + sizeof('@');

    // get ip and port
    sscanf(ptr_sip, "%[^:]", src_ip);
    //printf("src_ip:%s\n", src_ip);
    if (strnstr(src_ip, ".", 4, true) == NULL)
        return 1;
    ptr_sport = ptr_sip + strlen(src_ip);
    if (*ptr_sport == ':')
    {
        ptr_sport += sizeof(':');
        sscanf(ptr_sport, "%[0-9]", src_port);
    }
    else 
        ptr_sport = NULL;

    inet_ultoa(put->src_ip, cli_ip);
    
    // replace ip and port
    if (ptr_sport != NULL)
    {
        sprintf(r_src, "%s:%s", src_ip, src_port);
        sprintf(r_dst, "%s:%d", dst_ip, dst_port);
        //sprintf(r_dst, "%s:%d", dst_ip, 7100);
    }
    else
    {
        sprintf(r_src, "%s", src_ip);
        sprintf(r_dst, "%s", dst_ip);
    }
    printf("replace by key: [%s]--[%s]\n", r_src, r_dst);
    strreplace_pos(ptr, NULL, ut_buf, r_src, r_dst, 1, pack_len);

    return 1;
}

int replace_received(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    const static char FLG_RECEIVED[] = "received=";
    char src_received[16] = {0};
    char cli_ip[16] = {0};
    char *ptr = NULL;
    char *ptr_endl = NULL;
    char r_src[64] = {0};
    char r_dst[64] = {0};

    if ((ptr = strnstr(*ut_buf, FLG_RECEIVED, *pack_len, false)) == NULL)
        return 1;
    ptr += sizeof(FLG_RECEIVED)-1;
    ptr_endl = strnstr(ptr, "\r\n", *pack_len - (ptr - *ut_buf), true);
    if ((ptr_endl == NULL) || ((ptr_endl - ptr) > 15))
        return 1;
    sscanf(ptr, "%[^\r\n]", src_received);

    if (src_received[0] == 0)
        return 1;
    if (strnstr(src_received, ".", 4, true) == NULL)
        return 1;

    //printf("src_received:%s\n", src_received);
    inet_ultoa(put->src_ip, cli_ip);
    sprintf(r_src, "%s%s", FLG_RECEIVED, src_received);
    sprintf(r_dst, "%s%s", FLG_RECEIVED, cli_ip);
    //printf("received replace from %s to %s\n", r_src, r_dst);
    strreplace_pos(NULL, NULL, ut_buf, r_src, r_dst, 1, pack_len);

    return 1;
}

/*
int replace_received(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    const static char FLG_RECEIVED[] = "received=";
    char src_received[16] = {0};
    char l_ip[16] = {0};
    char *ptr = NULL;
    char *ptr_endl = NULL;
    char r_src[64] = {0};
    char r_dst[64] = {0};

    if ((ptr = strnstr(*ut_buf, FLG_RECEIVED, *pack_len, false)) == NULL)
        return 1;
    ptr += sizeof(FLG_RECEIVED)-1;
    ptr_endl = strnstr(ptr, "\r\n", *pack_len - (ptr - *ut_buf), true);
    if ((ptr_endl == NULL) || ((ptr_endl - ptr) > 15))
        return 1;
    sscanf(ptr, "%[^\r\n]", src_received);

    if (src_received[0] == 0)
        return 1;
    if (strnstr(src_received, ".", 4, true) == NULL)
        return 1;

    //printf("src_received:%s\n", src_received);
    inet_ultoa(__gg.outer_addr, l_ip);
    sprintf(r_src, "%s%s", FLG_RECEIVED, src_received);
    sprintf(r_dst, "%s%s", FLG_RECEIVED, l_ip);
    //printf("received replace from %s to %s\n", r_src, r_dst);
    strreplace_pos(NULL, NULL, ut_buf, r_src, r_dst, 1, pack_len);

    return 1;
}
*/

int replace_via_by_addr(pvp_uthttp put, char **ut_buf, u32 *pack_len, const char *ip, int port)
{
    const static char SIP_FLAG_VIA[] = "Via: SIP/2.0/UDP ";
    char ip_via[16] = {0};
    char port_via[16] = {0};
    //char d_ip[16] = {0};
    //char *dst_ip = NULL;
    char *ptr = NULL;
    char *ptr_endl = NULL;
    char r_src[64] = {0};
    char r_dst[64] = {0};

    if ((ptr = strnstr(*ut_buf, SIP_FLAG_VIA, *pack_len, false)) == NULL)
        return 1;
    ptr += sizeof(SIP_FLAG_VIA)-1;
    ptr_endl = strnstr(ptr, ":", *pack_len - (ptr - *ut_buf), true);
    if ((ptr_endl == NULL) || ((ptr_endl - ptr) > 15))
        return 1;
    sscanf(ptr, "%[^:]", ip_via);

    if (ip_via[0] == 0)
        return 1;
    if (strnstr(ip_via, ".", 4, true) == NULL)
        return 1;
    ptr += strlen(ip_via) + sizeof(':');
    sscanf(ptr, "%[0-9]", port_via);
    
    //printf("src_received:%s\n", src_received);
    //inet_ultoa(put->dip, d_ip);
    sprintf(r_src, "%s%s:%s", SIP_FLAG_VIA, ip_via, port_via);
    //sprintf(r_dst, "%s%s:%d", SIP_FLAG_VIA, d_ip, put->dport);
    sprintf(r_dst, "%s%s:%d", SIP_FLAG_VIA, ip, port);
    strreplace_pos(NULL, NULL, ut_buf, r_src, r_dst, 1, pack_len);

    //update_content_len(ut_buf, pack_len);

    return 1;
}

int replace_via_hik_register(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    char l_ip[16] = {0};
    //sprintf(r_dst, "%s:%d", l_ip, getsockport(put->svr_sock));
   inet_ultoa(__gg.outer_addr, l_ip);
    return replace_via_by_addr(put, ut_buf, pack_len, l_ip, getsockport(put->svr_sock));
}

int replace_via(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    char d_ip[16] = {0};
    inet_ultoa(put->dip, d_ip);
    return replace_via_by_addr(put, ut_buf, pack_len, d_ip, put->dport);
}

int replace_rport_received(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    const static char SIP_FLAG_VIA[] = "Via: SIP/2.0/UDP ";
    const static char SIP_FLAG_RPORT[] = "rport=";
    const static char SIP_FLAG_RECEIVED[] = "received=";

    char *prport = NULL;
    char *preceived = NULL;
    char rport[32] = {0};
    char received[32] = {0};
    char r_src[64] = {0};
    char r_dst[64] = {0};
    char l_ip[32] = {0};

    if ((strnstr(*ut_buf, SIP_FLAG_VIA, *pack_len, false)) == NULL)
        return 1;
    if ((prport = strnstr(*ut_buf, SIP_FLAG_RPORT, *pack_len, false)) == NULL)
        return 1;
    prport += sizeof(SIP_FLAG_RPORT)-1;
    if ((preceived = strnstr(*ut_buf, SIP_FLAG_RECEIVED, *pack_len, false)) == NULL)
        return 1;
    preceived += sizeof(SIP_FLAG_RECEIVED)-1;

    sscanf(prport, "%[^;]", rport);
    sscanf(preceived, "%[0-9.]", received);
    // replace rport
    sprintf(r_src, "%s%s;", SIP_FLAG_RPORT, rport);
    sprintf(r_dst, "%s%d;", SIP_FLAG_RPORT, getsockport(put->svr_sock));
    strreplace_pos(NULL, NULL, ut_buf, r_src, r_dst, 1, pack_len);
    // replace ip
    inet_ultoa(__gg.outer_addr, l_ip);
    sprintf(r_src, "%s%s", SIP_FLAG_RECEIVED, received);
    sprintf(r_dst, "%s%s", SIP_FLAG_RECEIVED, l_ip);
    strreplace_pos(NULL, NULL, ut_buf, r_src, r_dst, 1, pack_len);

    return 1;
}

int do_sip_replace_invite(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    const static char FLG_INIP4[] = "IN IP4 ";
    char r_src[64] = {0};
    char r_dst[64] = {0};
    char src_ip[16] = {0};
    char l_ip[16] = {0};
    char *ptr = NULL;

    if ((ptr = strnstr(*ut_buf, FLG_INIP4, *pack_len, true)) != NULL)
    {
        ptr += sizeof(FLG_INIP4)-1;
        inet_ultoa(__gg.outer_addr, l_ip);
        sscanf(ptr, "%[0-9.]", src_ip);
        sprintf(r_src, "%s%s", FLG_INIP4, src_ip);
        sprintf(r_dst, "%s%s", FLG_INIP4, l_ip);
        strreplace_pos(NULL, NULL, ut_buf, r_src, r_dst, -1, pack_len);
        update_content_len(ut_buf, pack_len);
    }

    return 1;
}

int do_ferry_sip_request_register(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    const static char FLG_REG[] = "REGISTER sip:";
    char ip[16] = {0};
    char port[8] = {0};
    char dip[16] = {0};
    //char src_ip[16] = {0};
    //u16  src_port = 0;
    char l_ip[16] = {0};
    //u16  l_port = 0;
    char r_src[64] = {0};
    char r_dst[64] = {0};
    char line[256] = {0};
    char *ptr = NULL;

    /*
    ptr = *ut_buf + sizeof(FLG_REG)-1;
    sscanf(ptr, "%[^:]", ip);
    sscanf(ptr + strlen(ip) + sizeof(':'), "%[0-9]", port);
*/
    if ((ptr = (char*)memmem(*ut_buf, *pack_len, "\r\n", 2)) == NULL)
        return -1;
    memcpy(line, *ut_buf, ptr - *ut_buf);

    puts(*ut_buf);
    puts("");
    char ssid[32] = {0};
    ptr = *ut_buf + sizeof(FLG_REG) - 1;

    if (memmem(line, strlen(line)+1, "@", 1) != NULL)
    {
        puts("-- 1");
        sscanf(ptr, "%[^@]", ssid);
        sscanf(ptr + strlen(ssid) + sizeof('@'), "%[^:]", ip);
        sscanf(ptr + strlen(ssid) + sizeof('@') + strlen(ip) + sizeof(':'), "%[0-9]", port);

        inet_ultoa(put->dip, dip);
        sprintf(r_src, "%s%s@%s:%s", FLG_REG, ssid, ip, port);
        sprintf(r_dst, "%s%s@%s:%d", FLG_REG, ssid, dip, put->dport);
        printf("src: %s\n", r_src);
        printf("dst: %s\n", r_dst);
        strreplace_pos(NULL,NULL, ut_buf, r_src, r_dst, 1, pack_len);
    }
    else
    {
        puts("-- 2");
        sscanf(ptr, "%[^:]", ip);
        ptr += strlen(ip) + sizeof(':');
        sscanf(ptr, "%[0-9]", port);

        inet_ultoa(put->dip, dip);
        sprintf(r_src, "%s%s:%s", FLG_REG, ip, port);
        sprintf(r_dst, "%s%s:%d", FLG_REG, dip, put->dport);
        strreplace_pos(NULL,NULL, ut_buf, r_src, r_dst, 1, pack_len);
    }

    // replace contact
    //inet_ultoa(put->src_ip, src_ip);
    inet_ultoa(__gg.outer_addr, l_ip);

    //sprintf(r_src, "%s:%d", src_ip, put->src_port);
    //sprintf(r_dst, "%s:%d", l_ip, getsockport(put->svr_sock));
    printf(">>>>>>sip reigditer port = %d\n", getsockport(put->svr_sock));
    do_sip_reply_replace_to_by_key(put, SIP_FLAG_CONTACT, l_ip, getsockport(put->svr_sock), ut_buf, pack_len);
    replace_via_hik_register(put, ut_buf, pack_len);
    //do_sip_reply_replace_to_by_key(put, SIP_FLAG_CONTACT, l_ip, 7100, ut_buf, pack_len);
    //strreplace_pos(NULL,NULL, ut_buf, r_src, r_dst, 1, pack_len);

    puts("================================");
    puts(*ut_buf);
    return 1;
}

int do_ferry_sip_request_message(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    /*
    char lip[16] = {0};
    inet_ultoa(__gg.inner_addr, lip);
    replace_cmd_ip_port(ut_buf, pack_len, lip, getsockport(put->svr_sock));
    */
    char dip[16] = {0};
    inet_ultoa(put->dip, dip);
    replace_cmd_ip_port(ut_buf, pack_len, dip, put->dport);

    return 1;
}

int replace_key_of_from(char **ut_buf, u32 *pack_len, char *ip_to, u16 port_to)
{
    const static char FLG_KEY_OF_FROM[] = "From: <sip:";
    char ip_of_from[16] = {0};
    char port_of_from[16] = {0};
    char r_src[64] = {0};
    char r_dst[64] = {0};
    char *ptr = NULL;
    char *ptr_ip = NULL;
    char *ptr_port = NULL;

    // get ip and port
    if ((ptr = strnstr(*ut_buf, FLG_KEY_OF_FROM, *pack_len, true)) == NULL)
        return 1;
    ptr += sizeof(FLG_KEY_OF_FROM)-1;
    if ((ptr = strnstr(ptr, "@", *pack_len - (ptr - *ut_buf), true)) == NULL)
        return 1;
    ptr += sizeof('@');
    ptr_ip = ptr;

    sscanf(ptr_ip, "%[^:]", ip_of_from);
    ptr_port = ptr_ip + strlen(ip_of_from) + sizeof(':');
    sscanf(ptr_port, "%[0-9]", port_of_from);

    // replace
    sprintf(r_src, "%s:%s", ip_of_from, port_of_from);
    sprintf(r_dst, "%s:%d", ip_to, port_to);
    strreplace_pos(ptr, NULL, ut_buf, r_src, r_dst, 1, pack_len);

    return 1;
}

