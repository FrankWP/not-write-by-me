#include "../vpheader.h"
#include "pm_proxy.h"

const static char _CLI_IP[] = "client_ip";
const static char _CLI_VS_BASE_PORT[] = "cli_vs_port";
const static char _FLG_BASE_PORT[] = "base_port";
const static char FLG_LOGON[] = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";
static char g_ums_ip[16] = {0};
static char g_cascade_ip[16] = {0};

int __keda2800_init(const char *parg)
{
    vp_uthtrans  ut;

    if (g_pm.proxy_type != P_TCP_PROXY)
        return -1;

    //if (init_segment_port(60128, 128, 50) < 0)
    if (init_segment_port(30128, 512, 256) < 0)
    {
        logdbg_out("ferry keda init: init segment pool port failed!");
        return -1;
    }

//    if ( ! pf_init_home())
    //{
        //logwar_out("ferry keda init: init process home failed!");
        //return -1;
    //}

    // used for cascade
	if (load_ip_pool() < 0)
    {
        logwar_out("ferry keda init: init ip pool failed!");
		return -1;
    }

	inet_ultoa(__gg.outer_addr, g_ums_ip);
	inet_ultoa(__gg.inner_addr, g_cascade_ip);
    memset(&ut, 0x00, sizeof(ut));

    ut.vphttp.session_tout = 60;
    ut.do_socket = __keda2800_socket;
    ut.do_close = __keda2800_close;
    ut.do_request = __keda2800_request;
    ut.do_reply = __keda2800_reply;

    if (load_portmap(&ut) == -1)
    {
        logwar_out("ferry keda init: load portmap failed!");
        return -1;
    }

    return 1;
}

void __keda2800_quit()
{
    destroy_segment_port();
    //pf_destroy_home();
    return;
}

int __keda2800_socket(pvp_uthttp put, int sockfd)
{
    /*
  if(5510 == put->dport){
    SAI  xaddr;
    ip_pool *ipp;
    memset(&xaddr, 0x00, sizeof(xaddr));

    ipp = ippool_search_by_desaddr(put->cli_addr);
    if (ipp == NULL)
      ipp = ippool_search_idle_addr(put->cli_addr);
  
    if (ipp == NULL) {
      syslog(LOG_INFO, "no idle ip at ippool.");
      return -1;
    }

    xaddr.sin_family = AF_INET;
    xaddr.sin_addr.s_addr = htonl(ipp->lip); //INADDR_ANY;
    xaddr.sin_port = htons(0);
    Setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR);

    if (bind(sockfd, (SA *)&xaddr, sizeof(xaddr)) < 0){
      char localip[32] = {0};
      inet_ultoa(ipp->lip, localip);
      loginf_fmt("__keda_socket: bind ip [%s] port [%d] random failed!\n", localip, xaddr.sin_port);
      return -1;
    }
  }
  */
  return 1;
}

static int do_keda2800_logon(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    //int       ret = -1;
    u32       inet_umsip = 0;
    u16       inet_vs_base_port = 0;
    u16		  inet_local_vs_base_port = 0;
    u16       host_local_vs_base_port = 0;
    u32       inet_cli_ip = 0;
    char *ptmp = NULL;

    ptmp = (char*)memmem(*ut_buf, *pack_len, FLG_LOGON, sizeof(FLG_LOGON)-1);
    if (ptmp != NULL)
    {
        ptmp += sizeof(FLG_LOGON)-1 + 16 + 3;

        inet_umsip = htonl(__gg.outer_addr);
        memcpy(&inet_cli_ip, ptmp, 4);
        memcpy(ptmp, &inet_umsip, 4);

        if (inet_cli_ip != htonl(put->src_ip))
            return 1;

        ptmp += 7;
        memcpy(&inet_vs_base_port, ptmp, 2);

        if ((host_local_vs_base_port = get_idle_segment_port()) == 0)
        {
            logdbg_out("ferry keda: get idle segment port failed!");
            return -1;
        }
        tp_set_data(_FLG_BASE_PORT, (char*)&host_local_vs_base_port, sizeof(host_local_vs_base_port));
        inet_local_vs_base_port = htons(host_local_vs_base_port);
        memcpy(ptmp, &inet_local_vs_base_port, 2);

        //const static int OFFSET_RECORD = 148;
        //const static int OFFSET_RECORD = 144;
        __kd_ga_video_proxy(__gg.outer_addr, ntohl(inet_cli_ip), host_local_vs_base_port, ntohs(inet_vs_base_port), PROXY_COUNT, 2, -1);
        //__kd_ga_video_proxy(__gg.outer_addr, ntohl(inet_cli_ip), host_local_vs_base_port + OFFSET_RECORD, ntohs(inet_vs_base_port) + OFFSET_RECORD, PROXY_COUNT, 2, -1);
        //__kd_ga_video_proxy(__gg.outer_addr, ntohl(inet_cli_ip), host_local_vs_base_port + OFFSET_RECORD, ntohs(inet_vs_base_port) + OFFSET_RECORD, PROXY_COUNT, 2, -1);
    }

    return 1;

}

int replace_cascade_addr(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    u32 inet_cascade_ip = 0;
    u32 inet_ums_ip = 0;
    inet_cascade_ip = htonl(__gg.inner_addr); //htonl(put->src_ip);//put->cli_addr.sin_addr.s_addr;
    inet_ums_ip = htonl(__gg.outer_addr);
    char *ptr = NULL;
    //char str_cascade_ip[16] = {0};

    //inet_ultoa(ntohl(inet_cascade_ip), str_cascade_ip);
    //inet_ultoa(put->src_ip, str_cascade_ip);

    //printf("uncompress len:%ld\n", len_msg_uncompress_l);
    //puts("-------- uncompress ----------------------------------------");
    //t_disbuf(pUncompress, len_msg_uncompress_l);

    //printf("cascade ip:%s\n", g_cascade_ip);
    //printf("ums ip:%s\n", g_ums_ip);
    //if (memcmp(pUncompress, &inet_cascade_ip, 4) == 0)
    //memcpy(pUncompress, &inet_ums_ip, 4);
    if (memcmp(*ut_buf, &inet_cascade_ip, 4) == 0)
        memcpy(*ut_buf, &inet_ums_ip, 4);
    if ((ptr = (char*)memmem(*ut_buf, *pack_len, g_cascade_ip, strlen(g_cascade_ip))) != NULL)
    {
        puts("**********************************************************");
        //memreplace_pos(NULL,NULL, ut_buf,pack_len, 1, g_cascade_ip,strlen(g_cascade_ip), g_ums_ip,strlen(g_ums_ip));
        strcpy(ptr, g_ums_ip);
    }

    return 1;
}

int replace_record_addr(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    if (*pack_len != 648)
        return 0;

    // Prepare argments
    char *ptr = NULL;
    u32 inet_ums_ip = 0;
    u32 inet_dest_ip = 0;	
    inet_ums_ip = htonl(__gg.outer_addr);
    u16 inet_dest_port = 0;
    u16 inet_ums_port = 0;
    u16 host_ums_port = 0;

    // Replace record ip of client open.
    ptr = *ut_buf + 38 * 16 + 11; // first client ip appear place.
    memcpy(&inet_dest_ip, ptr, 4);
    memcpy(ptr, &inet_ums_ip, 4);
    memcpy(ptr + 6, &inet_ums_ip, 4);
    memcpy(ptr + 12, &inet_ums_ip, 4);

    // Replace record port of client open.
    if ((host_ums_port = get_idle_segment_port()) == 0)
    {
        logdbg_out("ferry keda: get idle segment port failed!");
        return -1;
    }
    inet_ums_port = htons(host_ums_port);

    ptr = *ut_buf + 38 * 16 + 15; // first client port appear place.
    memcpy(&inet_dest_port, ptr, sizeof(inet_dest_port));
    memcpy(ptr, &inet_ums_port, sizeof(inet_ums_port));
    memcpy(ptr + 6, &inet_ums_port, sizeof(inet_ums_port));
    inet_ums_port = htons(host_ums_port + 2); 
    memcpy(ptr + 12, &inet_ums_port, sizeof(inet_ums_port));

    // Set thread private data
    tp_set_data(_FLG_BASE_PORT, (char*)&host_ums_port, sizeof(host_ums_port));

    //return __kd_ga_video_proxy(__gg.outer_addr, ntohl(inet_dest_ip), host_ums_port, ntohs(inet_dest_port), 1, 2, 60);
    return __kd_ga_video_proxy(__gg.outer_addr, ntohl(inet_dest_ip), host_ums_port, ntohs(inet_dest_port), 2, 2, 60);
}

int replace_video_stream_addr(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    const static char FLG_VS[] = "\xff\xff\x00\x00";
    char *ptr = NULL;
    u32 inet_dest_ip = 0;	//htonl(__gg.inner_addr);	
    u32 inet_ums_ip;
    inet_ums_ip = htonl(__gg.outer_addr);
    u16 inet_dest_port = 0;
    u16 inet_ums_port = 0;
    u16 host_ums_port = 0;

    //puts("----------------------- start video proxy 1 ------------------------------------");
    /*
       t_disbuf(*ut_buf, *pack_len);
       puts("----------------------- start video proxy 2 ------------------------------------");
       */

    //if ((ptr = (char*)memmem(*ut_buf, *pack_len, &inet_dest_ip, 4)) == NULL)
    //return 1;
    //if (ptr == *ut_buf)
    //return 1;

    if (memcmp(*ut_buf + 16 * 10 + 4, FLG_VS, sizeof(FLG_VS)-1) != 0)
        return 1;
    ptr = *ut_buf + 16 * 10 + 13;
    memcpy(&inet_dest_ip, ptr, 4);
    //puts("----------------------- start video proxy 3 ------------------------------------");

    // replace dest ip to ums ip
    memcpy(ptr, &inet_ums_ip, sizeof(inet_ums_ip));
    // get dest port
    ptr += sizeof(inet_dest_ip);
    memcpy(&inet_dest_port, ptr, sizeof(inet_dest_port));

    // replace dest port to ums port
    if ((host_ums_port = get_idle_segment_port()) == 0)
    {
        logdbg_out("ferry keda: get idle segment port failed!");
        return -1;
    }
    printf("host port:%d\n", host_ums_port);
    inet_ums_port = htons(host_ums_port);
    //t_disbuf(&inet_ums_port, 2);
    memcpy(ptr, &inet_ums_port, sizeof(inet_ums_port));

    //t_disbuf(*ut_buf, *pack_len);
    //puts("----------------------- start video proxy 4 ------------------------------------");

    // start proxy
    tp_set_data(_FLG_BASE_PORT, (char*)&host_ums_port, sizeof(host_ums_port));
    return __kd_ga_video_proxy(__gg.outer_addr, ntohl(inet_dest_ip), host_ums_port, ntohs(inet_dest_port), 1, 2, 6);
    //return 1;
}

int process_keda_comp_protocol(pvp_uthttp put, char **ut_buf, u32 *pack_len, int direction)
{
    const static char FLG_COMP[] = "\x02\x23";
    const static char FLG_RECORD[] = "\x78\xc0";
    const static int len_head = 39;
    const static int offset_msg_comp_len = 20;
    u16 inet_len_msg_compress = 0;
    u16 len_msg_uncompress = 0;
    unsigned long len_msg_compress_l = 0;
    unsigned long len_msg_uncompress_l = 0;
    unsigned char *pUncompress = NULL;
    unsigned char *ptr = NULL;
    int start_record = 0;

    //puts("------------- originality -----------------------------------");
    //t_disbuf((unsigned char*)*ut_buf, *pack_len);

    // check compress 
    if (memcmp(*ut_buf + 18, FLG_COMP, sizeof(FLG_COMP)-1) != 0)
	{
		//puts("-----------------------------");
        return 1;	// data is not compressed
	}

    if (memcmp(*ut_buf + 39, FLG_RECORD, sizeof(FLG_RECORD)-1) != 0)
        start_record = 1;

    memcpy(&inet_len_msg_compress, *ut_buf + offset_msg_comp_len, 2);
    inet_len_msg_compress = htons(ntohs(inet_len_msg_compress) - 4);

    memcpy(&len_msg_uncompress, *ut_buf + 41, 2);
    //printf("len uncom 1: %d\n", len_msg_uncompress);
    if (oss_malloc(&pUncompress, len_msg_uncompress) < 0)
    {
        logdbg_out("malloc uncompress memory failed!");
        return -1;
    }

    len_msg_uncompress_l = len_msg_uncompress;
    len_msg_compress_l = ntohs(inet_len_msg_compress);
    ptr = (unsigned char*)(*ut_buf + len_head + 4);
    //puts("--------- before uncompress -----------");
    //t_disbuf(ptr, len_msg_compress_l);
    if (zdecompress(ptr,len_msg_compress_l, pUncompress, &len_msg_uncompress_l) < 0)
    {
        oss_free(&pUncompress);
        logdbg_out("uncompress failed!");
        return 1;
    }

    printf("uncompress len:%ld\n", len_msg_uncompress_l);
    puts("-------- uncompress ----------------------------------------");
    t_disbuf(pUncompress, len_msg_uncompress_l);

    // -------------- PROCESS UNCOMPRESS DATA -------------------
    if (direction == DO_REQST)
        replace_cascade_addr(put, (char**)&pUncompress, (u32*)&len_msg_uncompress_l);
    else
    {
        replace_video_stream_addr(put, (char**)&pUncompress, (u32*)&len_msg_uncompress_l);
        if (start_record)
            replace_record_addr(put, (char**)&pUncompress, (u32*)&len_msg_uncompress_l);
    }
    
    // ReCompress
    unsigned char *pNewCompress = NULL;
    unsigned long len_new_compress = len_msg_uncompress + 128; // sometimes compress data is larger than that uncompress.
    oss_malloc(&pNewCompress, len_new_compress);    
    if (zcompress(pUncompress,len_msg_uncompress_l, pNewCompress,&len_new_compress) < 0)
    {
        oss_free(&pUncompress);
        oss_free(&pNewCompress);
        logdbg_out("compress failed!");
        return -1;
    }
    //puts("------------ new compress ----------------------------");
    //t_disbuf(pNewCompress, len_new_compress);

    // update data
    if ((ptr = (unsigned char*)realloc(*ut_buf, len_head + 4 + len_new_compress)) == NULL)
    {
        oss_free(&pUncompress);
        oss_free(&pNewCompress);
        logdbg_out("realloc failed!");
        return -1;
    }
    *ut_buf = (char*)ptr;
    *pack_len = len_head + 4 + len_new_compress;
    memcpy(*ut_buf + len_head + 4, pNewCompress, len_new_compress);
    len_new_compress += 4;
    u16 inet_len_new_compress = htons(len_new_compress);
    memcpy(*ut_buf + offset_msg_comp_len, &inet_len_new_compress, 2);

    //puts("-------- new data -----------");
    //t_disbuf((unsigned char*)*ut_buf, *pack_len);

    oss_free(&pUncompress);
    oss_free(&pNewCompress);

	return 1;
}

int do_cascade(pvp_uthttp put, char **ut_buf, u32 *pack_len, int direction)
{
    const static char FLG_COMP[] = "\x02\x23";
    //const static int OFFSET_MSG_COMP_LEN = 20;
    //u16 inet_len_msg_compress = 0;

    // check compress 
    if (memcmp(*ut_buf + 18, FLG_COMP, sizeof(FLG_COMP)-1) != 0)
        return 1;	// data is not compressed

    //memcpy(&inet_len_msg_compress, *ut_buf + OFFSET_MSG_COMP_LEN, 2);
    //inet_len_msg_compress = htons(ntohs(inet_len_msg_compress) - 4);

	return process_keda_comp_protocol(put, ut_buf, pack_len, direction);
}

static int video_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
  ip_pool *ipp;
  u16     port;
  
  /*Get local ip*/
  ipp = ippool_search_by_desaddr(put->cli_addr);
  if (ipp == NULL)
    ipp = ippool_search_idle_addr(put->cli_addr);
  if (ipp == NULL) {
    syslog(LOG_INFO, "reply no idle ip at ippool.");
    return -1;
  }
       
  /*Get video port*/
  memcpy(&port, *ut_buf + 29, 2);

  /*Start video proxy*/
//printf("lip:%s\n", inet_ultoa(ipp->lip, NULL));
//printf("cli_ip:%s\n", inet_ultoa(put->src_ip,NULL));
//printf("port:%d\n",ntohs(port));
    return run_vs_udp_proxy(ipp->lip, put->src_ip, ntohs(port), ntohs(port), 0, 12, __gg.ferry_port);
  //return __kd_ga_pre_vs_proxy(ipp->lip, put->src_ip, 
                              //ntohs(port), ntohs(port), 12);
 
}

int __keda2800_request(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    char *ptmp = NULL;
    const static char FLG_COMP[] = "\x02\x23";

    ptmp = (char*)memmem(*ut_buf, *pack_len, FLG_LOGON, sizeof(FLG_LOGON)-1);
    if (ptmp != NULL)
        return do_keda2800_logon(put, ut_buf, pack_len);

	if (*pack_len > 180)
		return 1;

    // check compress 
    if (0 == memcmp(*ut_buf + 18, FLG_COMP, sizeof(FLG_COMP)-1)){
      return do_cascade(put, ut_buf, pack_len, DO_REQST);
	}

    return 1;
}

int __keda2800_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    /*
    if (*pack_len > 40)
    {
        puts("------ reply ----------");
        t_disbuf(*ut_buf, *pack_len);
    }
    */
    const static char FLG_TVWALL[] = "\xe0\x4c";
    const static char FLG_COMP[] = "\x02\x23";
    const char VIDEO_FLG[3] = {0x01, 0x00, 0x50};
    u32 inet_cli_ip = 0;
    u16 inet_cli_port = 0;
    u16 local_pool_port = 0;

    // for tv wall
    if (memcmp(*ut_buf + 18, FLG_TVWALL, 2) == 0)
    {
        if (*pack_len > 35)
        {
            //puts("-------------- REPLY tv wall ---------------");
            memcpy(&inet_cli_ip, *ut_buf + 31, 4);
            //t_disbuf(*ut_buf, 36);
            //puts("cli_ip");
            //t_disbuf(&inet_cli_ip, 4);
            //puts("src_ip");
            //t_disbuf(&put->src_ip, 4);
            if (ntohl(inet_cli_ip) == put->src_ip)
            {
                memcpy(&inet_cli_port, *ut_buf + 29, 2);
                if ((local_pool_port = pplist_getidle_port()) <= 0)
                {
                    logwar_out("tv wall get idle port failed!");
                    return -1;
                }

                run_vs_udp_proxy(__gg.outer_addr, put->src_ip, local_pool_port, ntohl(inet_cli_port), 0, 12, __gg.ferry_port);

                // replace addr
                inet_cli_port = htons(local_pool_port);
                memcpy(*ut_buf + 29, &inet_cli_port, 2);
                inet_cli_ip = htonl(__gg.outer_addr);
                memcpy(*ut_buf + 31, &inet_cli_ip, 4);
                return 1;
            }
        }
    }
	
	if (0 == memcmp(*ut_buf + 18, FLG_COMP, sizeof(FLG_COMP)-1)){
      return do_cascade(put, ut_buf, pack_len, DO_REPLY);
	}else if(0 == memcmp(*ut_buf, VIDEO_FLG, sizeof(VIDEO_FLG))){
	  return video_reply(put, ut_buf, pack_len);
    }

  return 1;
}

int __keda2800_close(pvp_uthttp put, int sockfd)
{
    pid_t  pf_member_ids[PROXY_COUNT] = {0};
    char    flg[32] = {0};
    tdata  *ptdata = NULL;
    int     i = 0;
    u16     seg_port = 0;
    //ip_pool *ipp = NULL;

    sprintf(flg, "%lu", pthread_self());
    if ((ptdata = tp_get_data(flg)) != NULL)
    {
        memcpy(pf_member_ids, ptdata->data, sizeof(pid_t) * PROXY_COUNT);
        for (i = 0; i < PROXY_COUNT; ++i)
        {
            pf_dismiss_member(pf_member_ids[i]);
        }

        // get base port
        ptdata = tp_get_data(_FLG_BASE_PORT);
        if (ptdata != NULL)
        {
            memcpy(&seg_port, ptdata->data, 2);
            free_idle_segment_port(seg_port);
        }

        tp_rm_data(_FLG_BASE_PORT);
        tp_rm_data(_CLI_IP);
        tp_rm_data(_CLI_VS_BASE_PORT);
        tp_rm_data(flg);
    }

    /*
    ipp = ippool_search_by_desaddr(put->cli_addr);
    if (ipp != NULL)
      ippool_rset_flag(put->cli_addr);
      */

    return 1;
}

