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
const static char SIP_FLAG_FROM[] = "From:";
const static char SIP_FLAG_TO[] = "To:";

static const char *g_pmid = NULL;
//static FILTER  *g_flt = NULL;    // point to filter
//static int      g_e_tformat = E_TFORMAT_ERROR;


int __hik28181_init(const char *parg)
{
    if (parg == NULL)
    {
        logwar_out("hik 28181 init: invalid platform id");
        return -1;
    }
    g_pmid = parg;

    if (init_bind_port(7100, 100) < 0)
    {
        logwar_out("hik 28181 init: init bind port failed!");
        return -1;
    }

    init_record_server();
    load_portpool();

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
        logwar_out("加载协议类型失败!");
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

void __hik28181_quit()
{
    destroy_bind_port();
    destroy_portpool();
    user_clear_online();
    return;
}

int __hik28181_socket(pvp_uthttp put, int sockfd)
{
    puts("In amplysky28181 socket>>>>>>>>>>>>>>>>");
    u16 lport = 0;
    SAI  xaddr;
    memset(&xaddr, 0x00, sizeof(xaddr));

    //if (cert_is_enable() &&  ! test_user_cert(htonl(put->dip)))
        //return -1;

    if (put->dport == 7100)
    {
        if ((lport = get_idle_bind_port(NUM_ANY)) <= 0)
        {
            logwar_out("__hik28181_socket: get idle bind port failed!");
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
            loginf_fmt("__hik28181_socket: bind ip [%s] port [%d] failed!\n", localip, lport);
            return -1;
        }
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

int do_hik_rtsp_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
	char *pret = NULL;
	u16 nlport = 0;
	char dport[32] = {0};

	char lip[16] = {0};
	char dip[16] = {0};
	inet_ultoa(put->lip, lip);
	inet_ultoa(put->dip, dip);

	strreplace_pos(NULL,NULL, ut_buf, dip,lip, -1, pack_len);
	update_content_len(ut_buf, pack_len);

    // use for rtsp procotol to play video
    pret = (char*)memmem(*ut_buf, *pack_len, "RTSP/1.0", 8);
    if (pret != NULL) {
        /*
         *  start play video.
         *  client_port=10000-10001;server_port=6010-6011;
         */
        if (strstr(*ut_buf, "client_port") != NULL &&
                strstr(*ut_buf, "server_port") != NULL)
        {
            char      sport[8];
            char      camera_id[32];
            clivlist *pn = NULL;
            //clivlist *pnode = NULL;

            pret = strstr(*ut_buf, (char*)"server_port");
            sscanf((char *)pret + strlen((char*)"server_port") + 1, "%[^-]", dport);

            if ((nlport = pplist_getidle_port_x()) == 0) {
                return -1;
            }

            sprintf(sport, "%d", nlport);

            if (oss_malloc(&pn, sizeof(clivlist)) < 0) {
                return -1;
            }

            pn->lip = put->lip;
            pn->dip = put->dip;
            pn->lvport = nlport;
            pn->dvport = (u16)atoi(dport);
            pn->platform_id = put->platform_id;
            pn->vstream_tout = put->session_tout;

            get_virtual_cameraid(camera_id);
            strcpy(pn->camera_id, camera_id);

            if (__start_vs_tcp_proxy(pn, true, __gg.ferry_port) < 0)
            //if (start_video_stream_proxy(pn) < 0) 
            {
                free(pn);
                return -1;
            }
            free(pn);

            if (strreplace(ut_buf, dport, sport, REPLACE_ONE, pack_len) < 0) {
                return -1;
            }
        }
    }

	return 1;
}

int hik_rtsp_replace(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    const static char FLG_MEDIA_URL[] = "<Mediaurl>rtsp://";
    char *ptr = NULL;
    char rtsp_ip[16] = {0};
    int  rtsp_port = 0;
    int  lport = 0;
    char r_src[64] = {0};
    char r_dst[64] = {0};
    char l_ip[16] = {0};

    if ((ptr = (char*)memmem(*ut_buf, *pack_len, FLG_MEDIA_URL, sizeof(FLG_MEDIA_URL)-1)) == NULL)
        return 1;
    ptr += sizeof(FLG_MEDIA_URL)-1;

    // get rtsp ip and port
    sscanf(ptr, "%[^:]", rtsp_ip);
    ptr += strlen(rtsp_ip) + sizeof(':');
    sscanf(ptr, "%d", &rtsp_port);

    // start proxy
    if ((lport = x_search_server(rtsp_ip, rtsp_port)) == 0)
    {
        if ((lport = x_set_server(rtsp_ip, rtsp_port)) == 0)
        {
            logwar_out("get idle rtsp port failed!");
            return -1;
        }
        load_tcp_proxy_simple_n(T_DETACH, put->platform_id, put->session_tout, put->peerip,
                __gg.outer_addr, lport, inet_atoul(rtsp_ip), rtsp_port,
                NULL, NULL, NULL, do_hik_rtsp_reply, NULL);
    }

    inet_ultoa(__gg.outer_addr, l_ip);
    sprintf(r_src, "%s%s:%d", FLG_MEDIA_URL, rtsp_ip, rtsp_port);
    sprintf(r_dst, "%s%s:%d", FLG_MEDIA_URL, l_ip, lport);
    strreplace_pos(NULL,NULL, ut_buf, r_src, r_dst, 1, pack_len);

    return 1;
}

int do_ferry_sip_request_200ok(pvp_uthttp put, char **ut_buf, u32 *pack_len);
/*
{
    char dip[16] = {0};
    char src_ip[16] = {0};
    //u16  src_port = 0;
    char l_ip[16] = {0};
    char r_src[64] = {0};
    char r_dst[64] = {0};

    inet_ultoa(put->dip, dip);
    replace_via(put, ut_buf, pack_len);
    replace_key_of_from(ut_buf, pack_len, dip, put->dport);

    // replace contact
    inet_ultoa(put->src_ip, src_ip);
    inet_ultoa(__gg.outer_addr, l_ip);
    sprintf(r_src, "%s:%d", src_ip, put->src_port);
    sprintf(r_dst, "%s:%d", l_ip, getsockport(put->svr_sock));
    strreplace_pos(NULL,NULL, ut_buf, r_src, r_dst, 1, pack_len);

    hik_rtsp_replace(put, ut_buf, pack_len);

    return 1;
}
*/

int __hik28181_request(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    int res = 1;
    char lip[16] = {0};
    char dip[16] = {0};
    
    puts("In hik 28181 request>>>>>>>>>>>>>>>>");
    //printf("dport:%d\n", put->dport);
    //printf("sport:%d\n", put->src_port);
        //char cmd[16] = {0};
        //memcpy(cmd, *ut_buf, sizeof(cmd)-1);
        //puts(cmd);

    if (sip_is(*ut_buf, SIP_FLAG_REGISTER))
    {
        do_ferry_sip_request_register(put, ut_buf, pack_len);
    }
    else if (sip_is(*ut_buf, SIP_FLAG_MESSAGE))
    {
        inet_ultoa(__gg.outer_addr, lip);
        inet_ultoa(put->dip, dip);
        do_ferry_sip_request_message(put, ut_buf, pack_len);
        replace_via(put, ut_buf, pack_len);
        puts("======= replace key 1============");
        do_sip_reply_replace_to_by_key(put, SIP_FLAG_CONTACT, lip, getsockport(put->svr_sock), ut_buf, pack_len);
        do_sip_reply_replace_to_by_key(put, SIP_FLAG_FROM, lip, getsockport(put->svr_sock), ut_buf, pack_len);
        do_sip_reply_replace_to_by_key(put, SIP_FLAG_TO, dip, put->dport, ut_buf, pack_len);
        puts("======= replace key 2============");
        //do_sip_reply_replace_to_by_key(put, "To: <sip:", dip, put->dport, ut_buf, pack_len);
    }
    else if (sip_is(*ut_buf, SIP_FLAG_OK))
    {
        do_ferry_sip_request_200ok(put, ut_buf, pack_len);
    }
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

    update_content_len(ut_buf, pack_len);

    return res;
}

/*
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
*/

int get_expires(char *ut_buf);

int __hik28181_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    const static char FLG_200ok[] = "SIP/2.0 200 OK";

    //char sip_cmd[64] = {0};

    puts("in hik 28181 reply>>>>>>>>>>>>>>>");
    // filter data
    //time_t t_now = time(NULL);

    /*
    if ( !fltck_otm(g_flt, t_now))
        return -1;

    if ( !fleck_osip(g_flt, put->cli_addr.sin_addr.s_addr, 0))
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
    //if (strncmp(*ut_buf, FLG_200ok, sizeof(FLG_200ok)-1) == 0)
    if(memmem(*ut_buf, *pack_len, FLG_200ok, sizeof(FLG_200ok) -1) != NULL)
    {
        puts("----------------- 200 OK --------------------");
        if (strnstr(*ut_buf, "REGISTER", *pack_len, true) != NULL)
        {
            char cli_ip[16] = {0};
            if (get_expires(*ut_buf) == 3600)
            {
                puts("------------------ user online");
                inet_ultoa(put->src_ip, cli_ip);
                user_online(cli_ip, cli_ip, g_pmid);    
            }
            else if (get_expires(*ut_buf) == 0)
            {
                puts("------------------ user offline");
                inet_ultoa(put->src_ip, cli_ip);
                user_offline(cli_ip, cli_ip, g_pmid);    
            }
        }
    }

    return 1;
}

int __hik28181_close(pvp_uthttp put, int sockfd)
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

