#include "vp_uthttp.h"

int http_chunked_check(char *str, u32 len)
{
    char *pc, *ph;

    pc = (char*)memmem(str, len, HTTP_CHUNK_CHK, strlen(HTTP_CHUNK_CHK));
    ph = (char*)memmem(str, len, HTTP_HEAD_END, strlen(HTTP_HEAD_END));

    if (pc == NULL || ph == NULL)
        return -1;

    return 0;
}

int http_chunked_deal(char **reqst, char *buf, u32 *total, int ret, int chunked)
{
    int  tail;
    int  tail2;

    if (chunked == 0) {
        if (oss_malloc((void *)reqst, ret) < 0)
            return -1;
    } else {
        *reqst = (char *)realloc(*reqst, *total + ret);
        if (*reqst == NULL)
            return -1;
    }

    memcpy(*reqst + *total, buf, ret);
    *total += ret;

    tail = *total - (sizeof(HTTP_CHUNK_END)-1);
    tail2 = *total - (sizeof(HTTP_CHUNK_END2)-1);
    
    // notify: this can not use strstr(HTTP_CHUNK_END)
    if (!memcmp(*reqst + tail, HTTP_CHUNK_END, sizeof(HTTP_CHUNK_END)-1))
        return 1;
    if (!memcmp(*reqst + tail2, HTTP_CHUNK_END2, sizeof(HTTP_CHUNK_END2)-1))
        return 1;

    return 0;
}

int http_chunked_exchange(char *str, u32 lbody, u32 *total)
{
    int  ret;
    char chunk[64];
    char conte[64];

    memset(chunk, 0x00, sizeof(chunk));
    memcpy(chunk, HTTP_CHUNK_CHK, strlen(HTTP_CHUNK_CHK));
    sprintf(conte, "Content-Length: %d", lbody);

    ret = strreply(&str, chunk, conte, REPLACE_ONE, total);
    if (ret < 0){
    //printf("xxxxxxxxxxxx\n");
        return -1;
    }
    return 0;
}

int http_chunk_content(char * str)
{
    char *p;
    int  lhead;

    p = strstr(str, HTTP_HEAD_END);
    if (p != NULL)
        lhead = p - str + strlen(HTTP_HEAD_END);

    return lhead;
}

int http_chunked_change(char * str, u32 * rt)
{
    int  lbody = 0;
    int  len = 0;
    int  lhead;
    char hex[8];
    char *pts, *ps;
    int i;

    pts = (char *)malloc(*rt);
    if (pts == NULL) {
        printf("`chunk_change` malloc failed\n");
        return -1;
    }

    lhead = http_chunk_content(str);

    ps = str;
    memset(pts, 0x00, *rt);
    memcpy(pts, str, lhead); // copy the http chunked head to he new buf
    str = str + lhead;
    for (;;) {
        sscanf(str, "%x", &len);
        //sscanf(str, "%s", hex);
        memcpy(hex,str,8);
        i = 0;
        while (1){
            if (i > 7) {
                *(hex+i) = 0;
                break;
            }
            if (*(hex+i) == 0xa || *(hex+i) == 0xd){
                *(hex+i) = 0;
                break;
            }
            i++;
        }

        if (len == 0)
            break;
        memcpy(pts + lhead + lbody, str + strlen(hex) + 2, len);
        str = str +  strlen(hex) + len + 4;
        lbody += len;
    }
    str = ps;
    memset(str, 0x00, *rt);
    //lbody += 1;
    *rt = lhead + lbody;
    memcpy(str, pts, *rt);
    free(pts);

    if (http_chunked_exchange(str, lbody, rt) == -1)
        return -1;

    return 0;
}

int http_chunked_mode(char **reqst, char *buf, int ret, u32 *tl, int *chk)
{
    int retval;

    retval = http_chunked_deal(reqst, buf, tl, ret, *chk);
    if (retval < 0)
        return -1;
    if (retval == 0) {
        *chk = 1;
        return 0;
    }

    *chk = 0;
    if (http_chunked_change(*reqst, tl) < 0)
        return -1;
    return 1;
}

int http_parse_req_head(u32 *hlen, u32 *blen, char *dbuf)
{
    char bbuf[6];
    char *ph, *pb;

    ph = strstr(dbuf, HTTP_HEAD_END);
    if (strlen(dbuf) == 0 || ph == NULL)
        return -1;

    pb = strstr(dbuf, CONTENT_LENGTH);
    if (pb != NULL) {
        sscanf(pb + 16, "%[^\r\n]", bbuf);  // Content-Length: 4096
        *blen = atoi(bbuf);
    } else
        return -1;
    *hlen = ph - dbuf + strlen(HTTP_HEAD_END);

    return 0;
}

/*
 *   @ Function: completely read data from client or server
 *   @ reqst:  a new buf to save the data from client or server send
 *   @ dbuf:   read data from client or server
 *   @ ret:    the return value which call send or recv
 *   @ dtotal: the cache of save data from client or server
 */
int http_parse_req_data(char **reqst, char *dbuf, int ret,
                        u32 *dtotal, u32 *hlen, u32 *blen)
{
    int retv, rt;

    rt = *hlen + *blen - ret;

    if (*dtotal > SIP_MAX_SIZE) {
        syslog(LOG_INFO, "parse_req_http_data() no memory available");
        return -1;
    }

    if (*dtotal == 0) {
        if (oss_malloc((void *)reqst, ret + 1) < 0)
            return -1;
    } else {
        *reqst = (char *)realloc(*reqst, *dtotal + ret + 1);
        if (*reqst == NULL) {
            syslog(LOG_INFO, "parse_req_http_data() Insufficient memory available");
            return -1;
        }
    }

    memcpy(*reqst + *dtotal, dbuf, ret);
    retv = (rt <= 0 ? 0 : 1); // have no finish read the cache data if rt == 1

    *dtotal += ret;
    *blen = *blen - (ret - *hlen); // first recount http body len
    *hlen = 0;

    return retv;
}

int ut_parse_req_data(char **reqst, char *dbuf, int ret, u32 *dtotal)
{
    if (*dtotal == 0) {
        if (oss_malloc((void *)reqst, ret + 1) < 0)
            return -1;
    }
    memcpy(*reqst, dbuf, ret);
    *dtotal += ret;
    return 0;
}

int http_general_mode(char **reqst, char *buf, int ret, u32 *tl, u32 *hl, u32 *bl)
{
    int retval;

    /* check the data whether is http reqst head */
    if (*tl == 0) {
        if (http_parse_req_head(hl, bl, buf) < 0) {
            if (ut_parse_req_data(reqst, buf, ret, tl) < 0) /* do not have http head */
                return -1;
            return 1;
        }
    }
    retval = http_parse_req_data(reqst, buf, ret, tl, hl, bl); /* parse http boday */
    if (retval < 0)
        return -1;
    if (retval > 0)
        return 0;

    return 1;
}

int x_sendto_xy(int sockfd, char *buf, int len, int flags, struct sockaddr *src, 
          struct sockaddr *to, socklen_t tolen, vp_uthttp *pvp_arg)
{
    int    ret;
    SAI    to_addr;
    SAI    src_addr;
    SAI    peer;
    vp_ferry_udp_req_t  req;

    if (to == NULL)
        return -1;

    memset(&req, 0x00, sizeof(req));
    to_addr = *(struct sockaddr_in *)to;
    src_addr = *(struct sockaddr_in*)src;

    init_sockaddr(&peer, __gg.peer_priv_addr, __gg.ferry_port);

    req.sip = src_addr.sin_addr.s_addr;
    req.sport = src_addr.sin_port;
    req.dip = to_addr.sin_addr.s_addr;
    req.dport = to_addr.sin_port;
    req.bind_video_ip = htonl(pvp_arg->bind_video_ip);
    req.bind_video_port = htons(pvp_arg->bind_video_port);

    memcpy(buf, &req, sizeof(req));

    ret = sendto(sockfd, buf, len, flags, (struct sockaddr *)&peer, sizeof(peer));

    return ret;
}

int tcp_connect(int sersock, int tm_out, pvp_uthtrans puthtrans)
{
    int ret = -1;
    SAI  peer;
    u16 stofy =0;
    u16 ctofy =0;
    vp_ferry_tcp_req_t  req;
	tset_arg *targ = NULL;

    init_sockaddr(&peer, __gg.peer_priv_addr, __gg.ferry_port);

    /* first connect peer host */
    if (Connect(sersock, (struct sockaddr *)&peer, sizeof(peer), tm_out) < 0)
        return -1;

    memset(&req, 0x00, sizeof(req));
    /* send dest host's address to peer mtp server */
    req.sip = puthtrans->vphttp.src_ip;
    req.sport = puthtrans->vphttp.src_port;
    req.dip = puthtrans->vphttp.dip;
    req.dport = puthtrans->vphttp.dport;
    
	
    if (tset_is_flg_set(&puthtrans->vphttp.tset, TSET_USE_PROTO_UMS_CLIENT))
    {
        if ((targ = tset_fetch_arg(&puthtrans->vphttp.tset, TSET_USE_PROTO_UMS_CLIENT)) == NULL)
        {
            logwar_out("tcp_connect: get thread arg ferry_client failed!");
            return -1;
        }
        ctofy = targ->n;
        puts("TSET_USE_PROTO_UMS_CLIENT");
    }
    req.ctofy = ctofy;

    if (tset_is_flg_set(&puthtrans->vphttp.tset, TSET_USE_PROTO_UMS_SERVER))
    {
        if ((targ = tset_fetch_arg(&puthtrans->vphttp.tset, TSET_USE_PROTO_UMS_SERVER)) == NULL)
		{
			logwar_out("tcp_connect: get thread arg ferry_server failed!");
			return -1;
		}
		stofy = targ->n;
        puts("TSET_USE_PROTO_UMS_SERVER");
    }
    req.stofy = stofy;

    req.bind_video_ip = puthtrans->vphttp.bind_video_ip; 
    req.bind_video_port = puthtrans->vphttp.bind_video_port; 

    if ((ret = Send(sersock, (char *)&req, sizeof(req), 0)) <= 0)
    {
        printf("tcp_connect ret:%d\n", ret);
        return -1;
    }

    return 0;
}

int tcp_accept(int lsn_sock, SAI *cliaddr, pvp_uthtrans puthtrans)
{
    int ret = -1;
    int cli_sock = -1;
    socklen_t  addrlen;
    vp_ferry_tcp_req_t req;
    u16 stofy =0;
    u16 ctofy =0;

    addrlen = sizeof(*cliaddr);

    if ((cli_sock = Accept(lsn_sock, (struct sockaddr *)cliaddr, &addrlen)) < 0)
        return -1;

    if ((ret = Recv(cli_sock, (char *)&req, sizeof(req), 0)) <= 0)
    {
        close_sock(&cli_sock);
        return -1;
    }

    puthtrans->vphttp.src_ip= req.sip;
    puthtrans->vphttp.src_port= req.sport;
    puthtrans->vphttp.dip= req.dip;
    puthtrans->vphttp.dport = req.dport;
    ctofy = req.ctofy;
    stofy = req.stofy;

    if (ctofy != 0)
    {
        tset_enable_proto_ums_client(&puthtrans->vphttp.tset, ctofy);
    }
    if (stofy != 0)
    {
        tset_enable_proto_ums_server(&puthtrans->vphttp.tset, stofy);
    }

    puthtrans->vphttp.bind_video_ip = req.bind_video_ip;
    puthtrans->vphttp.bind_video_port = req.bind_video_port;

    return cli_sock;
}

int run_vs_proxy(const char *type, u32 lip, u32 dip, u16 lport, u16 dport, int pmid, int tout, int ferry_port)
{
    int ret = -1;
    clivlist *pcvn = (clivlist *)malloc(sizeof(clivlist));
    if (pcvn == NULL)
        return -1;
    if (type == NULL)
    {
        logwar_out("run_vs_proxy: invalid type!");
        return -1;
    }

    pcvn->lip = lip;
    pcvn->dip = dip;
    pcvn->lvport = lport;
    pcvn->dvport = dport;
    pcvn->platform_id = pmid;
    pcvn->vstream_tout = tout;

    ret = __start_vs_proxy(pcvn, type, ferry_port, true);
    oss_free(&pcvn);

    return ret;
}

void set_trans_arg(vp_uthtrans *ptrans, int pmid, int tout, u32 peer_ip, 
		u32 lip, u16 lport,
		u32 dip, u16 dport,
        int (* do_socket)(pvp_uthttp put, int sockfd),
	    int (* do_recv)(pvp_uthttp put, char *buf, int *pack_len, int direction),
        int (* do_request)(pvp_uthttp phttp, char **buf, u32 * pack_len),
        int (* do_reply)(pvp_uthttp phttp, char **buf, u32 * pack_len),
        int (* do_close)(pvp_uthttp put, int sockfd))
{
	int data_cache = Y_CACHE;
	if ((do_request == NULL) && (do_reply == NULL))
		data_cache = N_CACHE;

    ptrans->vphttp.lip = lip;
    ptrans->vphttp.lport = lport;
    ptrans->vphttp.dip = dip;
    ptrans->vphttp.dport = dport;

	ptrans->vphttp.peerip = peer_ip;

    ptrans->vphttp.platform_id = pmid;
    ptrans->vphttp.data_cache = data_cache;
    ptrans->vphttp.session_tout = tout;
	tset_none(&ptrans->vphttp.tset);

	ptrans->do_socket = do_socket;
    ptrans->do_recv = do_recv;
    ptrans->do_request = do_request;
    ptrans->do_reply = do_reply;
    ptrans->do_close = do_close;
}

int __start_vs_proxy(clivlist *pcvn, const char *vs_type, u16 priv_port, bool use_pp)
{
    char       psmid[32] = {0};
    char       port[32] = {0};
    clivlist * psmvn = NULL;
    char     * arg[5] = {NULL};

    if ((pcvn == NULL) || (vs_type == NULL))
        return -1;

    sprintf(psmid, "%d", get_sharemem_pid());

    if ((psmvn = create_tuvs_smem(psmid)) == NULL)
        return -1;

    memcpy(psmvn, pcvn, sizeof(clivlist));

	sprintf(port, "%u", priv_port);

    arg[0] = (char *)vs_type;
    arg[1] = psmid;
    if (use_pp)
        arg[2] = (char*)"-p";
    else
        arg[2] = (char*)"-n";
	arg[3] = port;
    arg[4] = (char *)0;

    char sourceip[16] = {0};
    char destip[16] = {0};
    inet_ultoa(psmvn->lip, sourceip);
    inet_ultoa(psmvn->dip, destip);
    char iptmp[256] = {0};
    sprintf(iptmp, " ### run vs proxy --[%s]:  pmid:%d sip:%s sport:%d dip:%s dport:%d -- ferry_port:[%s]", vs_type, psmvn->platform_id, sourceip, psmvn->lvport, destip, psmvn->dvport, port);
    puts(iptmp);

    loginf_fmt("=====run vs proxy ======[%s]:  sip:%s sport:%d dip:%s dport:%d -- ferry_port:[%s]", vs_type, sourceip, psmvn->lvport, destip, psmvn->dvport, port);

    return start_vstream_proxy((char *)vs_type, arg);
}

int __start_vs_tcp_proxy(clivlist *pcvn, bool flags, u16 priv_port)
{
    return __start_vs_proxy(pcvn, (char*)V_TCP_PROXY, priv_port, flags);
}

int __start_vs_udp_proxy(clivlist *pcvn, bool flags, u16 priv_port)
{
    return __start_vs_proxy(pcvn, (char*)V_UDP_PROXY, priv_port, flags);
}

int run_vs_udp_proxy(u32 lip, u32 dip, u16 lport, u16 dport, int pmid, int tout, int ferry_port)
{
    int ret = -1;
    clivlist *pcvn = NULL;
    oss_malloc(&pcvn, sizeof(clivlist));
    if (pcvn == NULL)
        return -1;

    pcvn->lip = lip;
    pcvn->dip = dip;
    pcvn->lvport = lport;
    pcvn->dvport = dport;
    pcvn->platform_id = pmid;
    pcvn->vstream_tout = tout;

    ret = __start_vs_udp_proxy(pcvn, true, ferry_port);
    oss_free(&pcvn);

    return ret;
}

int run_vs_tcp_proxy(u32 lip, u32 dip, u16 lport, u16 dport, int pmid, int tout, int ferry_port)
{
    int ret = -1;
    clivlist *pcvn = NULL;
    oss_malloc(&pcvn, sizeof(clivlist));
    if (pcvn == NULL)
        return -1;

    pcvn->lip = lip;
    pcvn->dip = dip;
    pcvn->lvport = lport;
    pcvn->dvport = dport;
    pcvn->platform_id = pmid;
    pcvn->vstream_tout = tout;

    printf("run_vs_tcp_proxy: ferry_port:%d\n", ferry_port);
    ret = __start_vs_tcp_proxy(pcvn, true, ferry_port);
    oss_free(&pcvn);

    return ret;
}

int run_thread_udp_proxy(u32 lip, u32 dip, u16 lport, u16 dport, int tout)
{
    return run_thread_tout_udp_proxy(lip,dip, lport,dport, tout, false,false);
}

int run_thread_tcp_proxy(u32 lip, u32 dip, u16 lport, u16 dport, int tout)
{
    return run_thread_tout_tcp_proxy(lip,dip, lport,dport, tout, false,false);
}

int run_thread_tout_udp_proxy(u32 lip, u32 dip, u16 lport, u16 dport, int tout, bool tout_exit, bool port_free)
{
    vp_uthtrans *pudp = NULL;

    if (oss_malloc(&pudp , sizeof(vp_uthtrans)) < 0)
        return -1;

    set_trans_arg(pudp, 0, tout, 0, lip,lport, dip,dport,
        NULL,NULL,NULL,NULL,NULL);
    if (tout_exit)
        tset_thread_tout(&pudp->vphttp.tset, tout);
    if (port_free)
        tset_port_free(&pudp->vphttp.tset);

    return load_tcp_proxy(pudp, T_DETACH);

}

int run_thread_tout_tcp_proxy(u32 lip, u32 dip, u16 lport, u16 dport, int tout, bool tout_exit, bool port_free)
{
    vp_uthtrans *ptcp = NULL;

    if (oss_malloc(&ptcp, sizeof(vp_uthtrans)) < 0)
        return -1;

    set_trans_arg(ptcp, 0, tout, 0, lip,lport, dip,dport,
        NULL,NULL,NULL,NULL,NULL);
    if (tout_exit)
        tset_thread_tout(&ptcp->vphttp.tset, tout);
    if (port_free)
        tset_port_free(&ptcp->vphttp.tset);

    return load_tcp_proxy(ptcp, T_DETACH);
}

// for sip 
int replace_sip_contact(char **ppbuf, u32 *pbuf_len, char *ip_from, char *ip_to, int port_from, int port_to)
{
    const static char FLG_CONTACT[] = "\r\nContact: <";
    char *pContact = NULL;
    char *pAt = NULL;
    char r_src[64] = {0};
    char r_dst[64] = {0};

    // Contact: <sip:2001$00000#000000FE2E74BF80@192.168.200.2:5060>
    if ((pContact = (char*)memmem(*ppbuf, *pbuf_len, FLG_CONTACT, sizeof(FLG_CONTACT)-1)) == NULL)
    {
        logwar_out("replace_sip_contact: contact flag not found!");
        return -1;
    }
    pContact += sizeof(FLG_CONTACT)-1;

    if ((pAt = (char*)memmem(pContact, *pbuf_len - (pContact - *ppbuf), "@", sizeof("@")-1)) == NULL)
    {
        logwar_out("replace_sip_contact: '@' not found!");
        return -1;
    }
    pAt += sizeof("@") - 1;

    //sprintf(r_src, "%s:%d>", ip_from, port_from);
    //sprintf(r_dst, "%s:%d>", ip_to, port_to);
    sprintf(r_src, "%s:", ip_from);
    sprintf(r_dst, "%s:", ip_to);
	strreplace_pos(pAt,NULL, ppbuf, r_src,r_dst, 1, pbuf_len);

    return 1;
}

int  load_proxy_simple(bool is_tcp, int t_state, int pmid, int tout, u32 peer_ip,
        u32 lip, u16 lport, u32 dip, u16 dport,
        int (* do_socket)(pvp_uthttp put, int sockfd),
	    int (* do_recv)(pvp_uthttp put, char *buf, int *pack_len, int direction),
        int (* do_request)(pvp_uthttp phttp, char **buf, u32 * pack_len),
        int (* do_reply)(pvp_uthttp phttp, char **buf, u32 * pack_len),
        int (* do_close)(pvp_uthttp put, int sockfd))
{
    int ret = -1;
    vp_uthtrans *proxy_arg = NULL;

    if (oss_malloc(&proxy_arg, sizeof(vp_uthtrans)) < 0)
    {
        if (is_tcp)
            logwar_out("load_tcp_proxy_simple: malloc failed!");
        else
            logwar_out("load_udp_proxy_simple: malloc failed!");
        return -1;
    }
   
    set_trans_arg(proxy_arg, pmid, tout, peer_ip,
            lip, lport, dip, dport,
            do_socket,do_recv,do_request,do_reply,do_close);

    if (is_tcp)
        ret = load_tcp_proxy(proxy_arg, t_state);
    else
        ret = load_udp_proxy(proxy_arg, t_state);
    return ret;
}

int  load_tcp_proxy_simple_s(int t_state, int pmid, const char *tout, const char *peer_ip,
        const char *lip, const char *lport, const char *dip, const char *dport,
        int (* do_socket)(pvp_uthttp put, int sockfd),
	    int (* do_recv)(pvp_uthttp put, char *buf, int *pack_len, int direction),
        int (* do_request)(pvp_uthttp phttp, char **buf, u32 * pack_len),
        int (* do_reply)(pvp_uthttp phttp, char **buf, u32 * pack_len),
        int (* do_close)(pvp_uthttp put, int sockfd))
{
    
    if ((tout == NULL) || (peer_ip == NULL) || (lip == NULL) || (lport == NULL) || 
        (dip == NULL) || (dport == NULL))
    {
        logwar_out("load_tcp_proxy_simple_s: arguments error!");
        return -1;
    }

    return load_tcp_proxy_simple_n(t_state, pmid, atoi(tout), inet_atoul(peer_ip),
            inet_atoul(lip), atoi(lport), inet_atoul(dip), atoi(dport), 
            do_socket, do_recv, do_request, do_reply, do_close);
}

int  load_tcp_proxy_simple_n(int t_state, int pmid, int tout, u32 peer_ip,
        u32 lip, u16 lport, u32 dip, u16 dport,
        int (* do_socket)(pvp_uthttp put, int sockfd),
	    int (* do_recv)(pvp_uthttp put, char *buf, int *pack_len, int direction),
        int (* do_request)(pvp_uthttp phttp, char **buf, u32 * pack_len),
        int (* do_reply)(pvp_uthttp phttp, char **buf, u32 * pack_len),
        int (* do_close)(pvp_uthttp put, int sockfd))
{
    return load_proxy_simple(true, t_state, pmid, tout, peer_ip,
            lip, lport, dip, dport, 
            do_socket, do_recv, do_request, do_reply, do_close);
}
 
int  load_udp_proxy_simple_s(int t_state, int pmid, const char *tout, const char *peer_ip,
        const char *lip, const char *lport, const char *dip, const char *dport,
        int (* do_socket)(pvp_uthttp put, int sockfd),
	    int (* do_recv)(pvp_uthttp put, char *buf, int *pack_len, int direction),
        int (* do_request)(pvp_uthttp phttp, char **buf, u32 * pack_len),
        int (* do_reply)(pvp_uthttp phttp, char **buf, u32 * pack_len),
        int (* do_close)(pvp_uthttp put, int sockfd))
{
    if ((tout == NULL) || (peer_ip == NULL) || (lip == NULL) || (lport == NULL) || 
        (dip == NULL) || (dport == NULL))
    {
        logwar_out("load_udp_proxy_simple: arguments error!");
        return -1;
    }
    return load_udp_proxy_simple_n(t_state, pmid, atoi(tout), inet_atoul(peer_ip),
            inet_atoul(lip), atoi(lport), inet_atoul(dip), atoi(dport), 
            do_socket, do_recv, do_request, do_reply, do_close);
}

int  load_udp_proxy_simple_n(int t_state, int pmid, int tout, u32 peer_ip,
        u32 lip, u16 lport, u32 dip, u16 dport,
        int (* do_socket)(pvp_uthttp put, int sockfd),
	    int (* do_recv)(pvp_uthttp put, char *buf, int *pack_len, int direction),
        int (* do_request)(pvp_uthttp phttp, char **buf, u32 * pack_len),
        int (* do_reply)(pvp_uthttp phttp, char **buf, u32 * pack_len),
        int (* do_close)(pvp_uthttp put, int sockfd))
{
    return load_proxy_simple(false, t_state, pmid, tout, peer_ip,
            lip, lport, dip, dport, 
            do_socket, do_recv, do_request, do_reply, do_close);
}


