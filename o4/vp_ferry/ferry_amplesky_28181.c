#include "../vpheader.h"
#include "pm_proxy.h"

/*
 *  TODO:
 *  @date: 2012.8.13
 *  @introduce: there are three parts need to be replaced:REGISTER, INVITE and ACK.
 *  @steps: 
 *      
 *      1. REGISTER:    replace flag:   a. Register head
 *                                      b. Contact
 *                                      c. Authorization uri
 *      
 *      2. INVITE:      replace flag:   a. Invite head
 *                                      b. Contact
 *                                      c. o=... 0 0 IN IP4 (client ip)
 *                                      d. c=IN IP4 (client ip)
 *                                      e. m=video (client port) 
 *
 *      3. ACK          replace flag:   a. Ack head
 *                                      b. o=... 0 0 IN IP4 (server ip)
 *                                      c. c=IN IP4 (server ip)
 *                                      d. m=video (server port)
 *
 *      For the time being, we can only write several functions to replace the ip and port in the
 *      example which appears in the book of GB28181. In real work, more things needs to be done.
 *
 * */


struct _sessions
{
    time_t t;
    u32 ip;
    u16 port;
    int stat; // whether package can go throuth
};

const static char SIP_FLAG_REGISTER[] = "REGISTER";

const static char SDP_SIGN[] = "application/sdp";
const static char SIP_FLAG_MESSAGE[] = "MESSAGE ";
const static char SIP_FLAG_OK[] = "SIP/2.0 200 OK";
const static char SIP_FLAG_INVITE[] = "INVITE ";
const static char SIP_FLAG_BYE[] = "BYE ";
const static char SIP_FLAG_ACK[] = "ACK ";
const static char SIP_FLAG_INFO[] = "INFO ";
const static char SIP_FLAG_CONTACT[] = "Contact:";

static const char *g_pmid = NULL;
//static FILTER  *g_flt = NULL;    // point to filter
static int      g_e_tformat = E_TFORMAT_ERROR;

/*
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
    char tmp_line[256] = {0};

    if ((ptr = strnstr(*ut_buf, key, *pack_len, false)) == NULL)
        return 1;
    ptr += strlen(key);
    if ((ptr_sip = strnstr(ptr, "@", *pack_len - (ptr - *ut_buf), true)) == NULL)
        return 1;
    else
        ptr_sip = ptr_sip + sizeof('@');

    // get ip and port
    //sscanf(ptr_sip, "%[^:]", src_ip);
    sscanf(ptr_sip, "%[^\r\n]", tmp_line);
    if (strstr(tmp_line, ":") == NULL)
    {
        sscanf(tmp_line, "%[^<]", src_ip);
    }
    else
    {
        sscanf(tmp_line, "%[^:]", src_ip);
    }

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

int replace_via(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    const static char SIP_FLAG_VIA[] = "Via: SIP/2.0/UDP ";
    char ip_via[16] = {0};
    char port_via[16] = {0};
    char d_ip[16] = {0};
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
    inet_ultoa(put->dip, d_ip);
    sprintf(r_src, "%s%s:%s", SIP_FLAG_VIA, ip_via, port_via);
    sprintf(r_dst, "%s%s:%d", SIP_FLAG_VIA, d_ip, put->dport);
    strreplace_pos(NULL, NULL, ut_buf, r_src, r_dst, 1, pack_len);

    update_content_len(ut_buf, pack_len);

    return 1;
}
*/

int __amplesky28181_init(const char *parg)
{
    if (parg == NULL)
    {
        logwar_out("amplesky 28181 init: invalid platform id");
        return -1;
    }
    g_pmid = parg;

    if (init_bind_port(6060, 100) < 0)
    {
        logwar_out("amplesky 28181 init: init bind port failed!");
        return -1;
    }

    if (load_portpool() < 0)
    {
        logwar_out("amplesky 28181 init: load port pool failed!");
        return -1;
    }

    /*
    if ( ! modmysql_open(DB_NAME, 3))
        return -1;

    if ((g_flt = get_filter(parg)) == NULL)
    {
        loginf_out("初始过滤器失败!");
        return -1;
    }

    if ( ! load_proto_type_filter(g_flt))
    {
        logwar_out("加?协议类型失败!");
        return -1;
    }
        */

    /*
    if ( (g_e_tformat = load_transport_format_filter()) == E_TFORMAT_ERROR)
    {
        logwar_out("Failed init transport format filter");
        return -1;
    }
    */

    return 1;
}

void __amplesky28181_quit()
{
    destroy_bind_port();
    //user_clear_online();
    return;
}

int __amplesky28181_socket(pvp_uthttp put, int sockfd)
{
    u16 lport = 0;
    SAI  xaddr;
    memset(&xaddr, 0x00, sizeof(xaddr));

    //if (cert_is_enable() &&  ! test_user_cert(htonl(put->dip)))
        //return -1;

    if ((lport = get_idle_bind_port(NUM_ANY)) <= 0)
    {
        logwar_out("__amplesky28181_socket: get idle bind port failed!");
        return -1;
    }
    xaddr.sin_family = AF_INET;
    xaddr.sin_addr.s_addr = htonl(__gg.outer_addr); //INADDR_ANY;
    xaddr.sin_port = htons(lport);
    Setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR);

    if (bind(sockfd, (SA *)&xaddr, sizeof(xaddr)) < 0)
    {
        char localip[32] = {0};
        inet_ultoa(__gg.outer_addr, localip);
        loginf_fmt("__amplesky28181_socket: bind ip [%s] port [%d] failed!\n", localip, xaddr.sin_port);
        return -1;
    }
 
    /*
    char src_flag[32] = {0};
    gldata *gd = NULL;
    struct _sessions session;

    if (is_tms() && (g_pm.proxy_type == P_UDP_PROXY))
    {
        mod_vf_filter_init();
        if ( ! mod_vf_filter_check(EVF_H264))
        {
            sprintf(src_flag, "%d:%d", put->src_ip, put->src_port);

            if ((gd = gl_get_data(src_flag)) == NULL)
            {
                session.t = time(NULL);
                session.ip = put->src_ip;
                session.port = put->src_port;

                printf("new session 1 %s\n", src_flag);
                gl_set_data(src_flag, (char*)&session, sizeof(session));
                logwar_out("h264 被拒绝!");
            }
            else
            {
                memcpy(&session, gd->data, gd->len);
                if (time(NULL) - session.t > put->session_tout)
                {
                    sprintf(src_flag, "%d:%d", session.ip, session.port);
                    gl_rm_data(src_flag);
                }
            }
            return -1;
        }
    }
    */
    
    return 1;
}

int check_vsformat(pvp_uthttp put, char *pkg, u32 len_pkg)
{
    //rtpheader rtph;
    char src_flag[32] = {0};
    gldata *gd = NULL;
    struct _sessions session;
    int res = 1;

    sprintf(src_flag, "%d:%d", put->src_ip, put->src_port);
    if ((gd = gl_get_data(src_flag)) == NULL)
    {
        printf("new session 2 %s\n", src_flag);
        // video stream format check
        if ((g_e_tformat == E_TFORMAT_NONE) ||
                (g_e_tformat == E_TFORMAT_ERROR))
        {
            //logwar_out("All transport protocol are not allowed to through!");
            //return -1;
            res = -1;
        }

        if ((g_e_tformat & E_TFORMAT_RTP) != E_TFORMAT_RTP)
        {
            //if ( sample_rtph(pkg, len_pkg, &rtph))
            {
                //logwar_out("RTP transport protocol is not allowed to through!");
                //return -1;
                res = -2;
            }
        }

        session.t = time(NULL);
        session.ip = put->src_ip;
        session.port = put->src_port;
        session.stat = res;

        gl_set_data(src_flag, (char*)&session, sizeof(session));
        if (res == -1)
        {
            logwar_out("All transport protocol are not allowed to through!");
            return -1;
        }
        else if (res == -2)
        {
            logwar_out("RTP transport protocol is not allowed to through!");
            return -1;
        }
    }
    else
    {
        memcpy(&session, gd->data, gd->len);
        printf("session stat:%d\n", session.stat);
        if (session.stat < 0)
            return -1;
    }
    return 1;
}

/*
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
    char *ptr = NULL;

    ptr = *ut_buf + sizeof(FLG_REG)-1;
    sscanf(ptr, "%[^:]", ip);
    sscanf(ptr + strlen(ip) + sizeof(':'), "%[0-9]", port);

    inet_ultoa(put->dip, dip);
    sprintf(r_src, "%s%s:%s", FLG_REG, ip, port);
    sprintf(r_dst, "%s%s:%d", FLG_REG, dip, put->dport);
    strreplace_pos(NULL,NULL, ut_buf, r_src, r_dst, 1, pack_len);


    // replace contact
    //inet_ultoa(put->src_ip, src_ip);
    inet_ultoa(__gg.outer_addr, l_ip);
    //sprintf(r_src, "%s:%d", src_ip, put->src_port);
    //sprintf(r_dst, "%s:%d", l_ip, getsockport(put->svr_sock));
    do_sip_reply_replace_to_by_key(put, SIP_FLAG_CONTACT, l_ip, getsockport(put->svr_sock), ut_buf, pack_len);
    //strreplace_pos(NULL,NULL, ut_buf, r_src, r_dst, 1, pack_len);

    return 1;
}

int do_ferry_sip_request_message(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
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
*/

int do_ferry_sip_request_200ok(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    char dip[16] = {0};
    char src_ip[16] = {0};
    //u16  src_port = 0;
    char l_ip[16] = {0};
    char r_src[64] = {0};
    char r_dst[64] = {0};

    inet_ultoa(put->dip, dip);
    replace_via(put, ut_buf, pack_len);
    replace_rport_received(put, ut_buf, pack_len);
    replace_key_of_from(ut_buf, pack_len, dip, put->dport);

    // replace contact
    inet_ultoa(put->src_ip, src_ip);
    inet_ultoa(__gg.outer_addr, l_ip);
    sprintf(r_src, "%s:%d", src_ip, put->src_port);
    //sprintf(r_dst, "%s:%d", l_ip, getsockport(put->svr_sock));
    sprintf(r_dst, "%s:%d", l_ip, put->src_port);
    printf("------- replace contact -----------------------------------------------------\n");
    printf("r_src: %s\n", r_src);
    printf("r_dst: %s\n", r_dst);
    puts("-----------------------------------------------------------------------------------");
    strreplace_pos(NULL,NULL, ut_buf, r_src, r_dst, 1, pack_len);

    return 1;
}
/*
int do_sip_reply_ack(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    char cli_ip[16] = {0};

    inet_ultoa(put->src_ip, cli_ip);
    replace_cmd_ip_port(ut_buf, pack_len, cli_ip, put->src_port);

    return 1;
}
*/

int do_sip_reply_invite(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    const static char FLG_INIP4[] = "IN IP4 ";
    const static char FLG_VPORT[] = "m=video ";
    char cli_ip[16] = {0}; // outer server ip
    char   *pstr = NULL;
    char   sport[8] = {0};    /*Source port*/
    char r_src[64] = {0};
    char r_dst[64] = {0};
    char lip[16] = {0};
    char dip[16] = {0};
    char *ptr = NULL;
    u16 nlport = 0;
    char call_id[128] = {0};

    puts("******** 1");
    if ((pstr = strstr(*ut_buf, FLG_VPORT)) != NULL)
    {
    puts("******** 2");
    puts(*ut_buf);
        pstr += sizeof(FLG_VPORT)-1;
        sscanf(pstr, "%[0-9]", sport);
        if ((nlport = pplist_getidle_port_x()) == 0)
        {
            logwar_out("get idle port failed!");
            return -1;
        }

    puts("******** 3");
        // replace ip
        if ((ptr = strnstr(*ut_buf, FLG_INIP4, *pack_len, true)) != NULL)
        {
            ptr += sizeof(FLG_INIP4)-1;
            sscanf(ptr, "%[0-9.]", dip);
            inet_ultoa(__gg.outer_addr, lip);
            sprintf(r_src, "%s%s", FLG_INIP4, dip);
            //sprintf(r_dst, "%s%s", FLG_INIP4, g_value[L_AUTHIP]);
            sprintf(r_dst, "%s%s", FLG_INIP4, lip);
            strreplace_pos(NULL, NULL, ut_buf, r_src, r_dst, -1, pack_len);
        }
    puts("******** 4");
        // replace port
        sprintf(r_src, "%s%s", FLG_VPORT, sport);
        sprintf(r_dst, "%s%d", FLG_VPORT, nlport);
        strreplace_pos(NULL,NULL, ut_buf, r_src, r_dst, 1, pack_len);
        
        inet_ultoa(put->src_ip, cli_ip);

        // replace invite ip
        replace_cmd_ip_port(ut_buf, pack_len, cli_ip, put->src_port);

    puts("******** 5");
        // start proxy
        char camera_id[32] = {0};
        int ret = -1;
        clivlist *pcvn = NULL;
        if (oss_malloc(&pcvn, sizeof(clivlist)) < 0)
            return -1;
        get_virtual_cameraid(camera_id);

        strcpy(pcvn->visit_user, cli_ip);
        strcpy(pcvn->camera_id, camera_id);
        //if (is_tms())
            //pcvn->lip = __gg.inner_addr;
        //else
            pcvn->lip = __gg.outer_addr;
        pcvn->dip = inet_atoul(dip);
        pcvn->lvport = nlport;
        pcvn->dvport = atoi(sport);
        pcvn->platform_id = a_get_pmid();
        // pcvn->vstream_tout = put->session_tout;   //
        // 信令超时时间需要很长，如果视频流使用相同超时时间，会有大量已经使用完的视频进程逗留在系统中
        pcvn->vstream_tout = 60;
        pcvn->bind_video_port = nlport;

    puts("******** 6");
        if (get_call_id(*ut_buf, *pack_len, call_id, sizeof(call_id)) == NULL)
            logdbg_out("获取Call id 失败!");
        else if ( ! gl_set_data(call_id, (char*)&nlport, sizeof(nlport)))
            logdbg_out("记录Call id 失败!");
    
        ret = __start_vs_udp_proxy(pcvn, true, __gg.ferry_port + 1);
        oss_free(&pcvn);

        //sip_replace_contact(ut_buf, pack_len, g_value[L_AUTHIP], 5060);
        //do_sip_reply_replace_by_key(put, SIP_FLAG_CONTACT, ut_buf, pack_len);
    }

    return 1;
}

int __amplesky28181_request(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    int res = 1;
    char lip[16] = {0};
    char dip[16] = {0};
    
    //printf("dport:%d\n", put->dport);
    //printf("sport:%d\n", put->src_port);
        //char cmd[16] = {0};
        //memcpy(cmd, *ut_buf, sizeof(cmd)-1);
        //puts(cmd);
    puts("---------- REQUEST ----------");

    if (sip_is(*ut_buf, SIP_FLAG_REGISTER))
    {
    puts("---------- REQUEST 1 --------");
        do_ferry_sip_request_register(put, ut_buf, pack_len);
    }
    else if (sip_is(*ut_buf, SIP_FLAG_MESSAGE))
    {
    puts("---------- REQUEST 2 --------");
        inet_ultoa(__gg.outer_addr, lip);
        inet_ultoa(put->dip, dip);
        do_ferry_sip_request_message(put, ut_buf, pack_len);
        do_sip_reply_replace_to_by_key(put, SIP_FLAG_CONTACT, lip, getsockport(put->svr_sock), ut_buf, pack_len);
        do_sip_reply_replace_to_by_key(put, "To: <sip:", dip, put->dport, ut_buf, pack_len);
    }
    else if (sip_is(*ut_buf, SIP_FLAG_OK))
    {
    puts("---------- REQUEST 3 --------");
        do_ferry_sip_request_200ok(put, ut_buf, pack_len);
    }
    puts("---------- REQUEST 4 --------");
    do_sip_reply_invite(put, ut_buf, pack_len);
    //////////////////
    /*
       else if (sip_is(*ut_buf, SIP_FLAG_INVITE))
       {
       do_sip_reply_invite(put, ut_buf, pack_len);
       do_sip_reply_replace_via(put, ut_buf, pack_len);
       }
       else if (sip_is(*ut_buf, SIP_FLAG_BYE))
       {
       do_sip_reply_bye(put, ut_buf, pack_len);
       do_sip_reply_replace_via(put, ut_buf, pack_len);
       }
       else if (sip_is(*ut_buf, SIP_FLAG_ACK))
       {
       do_sip_reply_ack(put, ut_buf, pack_len);
       do_sip_reply_replace_via(put, ut_buf, pack_len);
       }
       else if (sip_is(*ut_buf, SIP_FLAG_INFO))
       {
       do_sip_reply_info(put, ut_buf, pack_len);
       do_sip_reply_replace_via(put, ut_buf, pack_len);
       }

       do_sip_reply_replace_by_key(put, SIP_FLAG_CONTACT, ut_buf, pack_len);
       do_sip_reply_replace_by_key(put, "From: <sip:", ut_buf, pack_len);
       */
/////////////////////
    puts("---------- REQUEST 5 --------");
    update_content_len(ut_buf, pack_len);
    puts("---------- REQUEST 6 --------");

    return res;
}

int get_expires(char *pkg)
{
    const static char FLG_EXPIRES[] = "Expires:";
    char expires[8] = {0};
    char *ptr = NULL;

    if (pkg == NULL)
        return -1;

    if ((ptr = strstr(pkg, FLG_EXPIRES)) == NULL)
        return -1;
    ptr += sizeof(FLG_EXPIRES)-1;
    sscanf(ptr, "%[^\r\n]", expires);

    return atoi(expires);
}

int __amplesky28181_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    const static char FLG_200ok[] = "SIP/2.0 200 OK";

    puts("---------- REPLY ----------");
    /*
    char sip_cmd[64] = {0};

    // filter data
    time_t t_now = time(NULL);

    if ( !fltck_otm(g_flt, t_now))
        return -1;

    if ( !fltck_osip(g_flt, put->cli_addr.sin_addr.s_addr, 0))
        return -1;
    if ( !fltck_odip(g_flt, htonl(put->dip), 0))
        return -1;

    if ( !fltck_oproto(g_flt, *ut_buf, *pack_len))
        return -1;

    //if ( ! fltck_oacl(g_flt, td->data, t_now, put->cli_addr.sin_addr.s_addr, 0, htonl(put->dip), 0))
        //return -1;
    
    sscanf(*ut_buf, "%[^\r\n]", sip_cmd);

    //if ( !fltck_ocmd(g_flt, *ut_buf))
        //return -1;
    if ( !fltck_ocmd(g_flt, sip_cmd))
        return -1;
    if ( !fltck_ostr(g_flt, *ut_buf, *pack_len, FILTER_DIR_C2S))
        return -1; 
        */

    //puts(*ut_buf);
    if (strncmp(*ut_buf, FLG_200ok, sizeof(FLG_200ok)-1) == 0)
    {
        //puts("----------------- 200 OK --------------------");
        if (strnstr(*ut_buf, "REGISTER", *pack_len, true) != NULL)
        {
            char cli_ip[16] = {0};
            if (get_expires(*ut_buf) == 3600)
            {
                puts("------------------ user online");
                inet_ultoa(put->src_ip, cli_ip);
                //user_online(cli_ip, cli_ip, g_pmid);    
            }
            else if (get_expires(*ut_buf) == 0)
            {
                puts("------------------ user offline");
                inet_ultoa(put->src_ip, cli_ip);
                //user_offline(cli_ip, cli_ip, g_pmid);    
            }
        }
    }

    return 1;
}

int __amplesky28181_close(pvp_uthttp put, int sockfd)
{
    gldata *gd = NULL;
    char src_flag[32] = {0};
    //struct _sessions session;

    set_idle_bind_port( getsockport(sockfd) );
    sprintf(src_flag, "%d:%d", put->src_ip, put->src_port);
    if ((gd = gl_get_data(src_flag)) != NULL)
        gl_rm_data(src_flag);

    return 1;
}

