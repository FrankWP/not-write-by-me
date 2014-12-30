#include "../vpheader.h"
#include "pm_proxy.h"

/*
 * HuNan ZhuZhou huasan platform
 */

static char g_cfg_value[C_TOTAL][32] = {{0}};

static ip_pool *get_idle_ip(pvp_uthttp put)
{
    ip_pool *ipp = NULL;

    ipp = ippool_search_by_desaddr(put->cli_addr);
    if (ipp == NULL) {
        ipp = ippool_search_idle_addr(put->cli_addr);
        if (ipp == NULL) {
            syslog(LOG_INFO, "no idle ip at ippool.");
            return ipp;
        }
    }
    return ipp;
}

/*
static int get_inet_ip_from_socket(int sockfd)
{
    struct sockaddr_in saddr;
    socklen_t len;
    if (getsockname(sockfd, (struct sockaddr*)&saddr, &len) < 0)
        return -1;
    return saddr.sin_addr.s_addr;
}
*/

static int start_vs_proxy(clivlist *pcvn, char *type)
{
    char      psmid[32];
    clivlist *psmvn = NULL;
    char     *arg[5] = {NULL};
	char	 ferry_port[8] = {0};
	sprintf(ferry_port, "%d", __gg.ferry_port);

    sprintf(psmid, "%d", get_sharemem_pid());
    if ((psmvn = create_tuvs_smem(psmid)) == NULL)
        return -1;
    memcpy(psmvn, pcvn, sizeof(clivlist));

    arg[0] = type;
    arg[1] = psmid;
    arg[2] = (char*)"-p";
    arg[3] = ferry_port;
	arg[4] = NULL;
    start_vstream_proxy(type, arg);

    return 1;
}

// start video stream proxy in this function
static int do_ferry_huasan_6060_vscmd_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    const static char flg_server[] = "asserver";
    const static int user_name_offset = sizeof(flg_server)-1 + 27;
	const static int addr_offset1 = sizeof(flg_server)-1 + 16 * 9 + 10;

	char *ptr = NULL;
	u16 port = 0;
	clivlist *pn = NULL;
    char flg_uname[16] = {0};
    u32 inet_cli_ip = -1;
    u32 inet_ums_ip = -1; //htonl(__gg.outer_addr);

	if ((ptr = (char*)memmem(*ut_buf, *pack_len, flg_server, sizeof(flg_server)-1)) == NULL)
        return 1;

    memcpy(flg_uname, ptr + user_name_offset, sizeof(flg_uname)-1);
    tdata *ptdata = tp_get_data(flg_uname);
    if (ptdata == NULL)
    {
        printf("cannot find client ip information");
        return 1;
    }
    // get client ip in mem
    memcpy(&inet_cli_ip, ptdata->data, 4);

    ptr += addr_offset1;
	if ((pn = (clivlist *)malloc(sizeof(clivlist))) == NULL)
        return -1;
    pn->platform_id = 0;

	// data is such as: eb 0e c0 a8 cd 8b
	// get dest port
	memcpy(&port, ptr, sizeof(port));
    ptr += sizeof(port);
    // replace ums ip to client ip
    /*
    inet_ums_ip = get_inet_ip_from_socket(put->svr_sock);
    inet_ultoa(ntohl(inet_ums_ip), t);
    printf("ums_ip is: %s\n", t);
    */

    inet_ums_ip = htonl(__gg.outer_addr);
    memreplace_pos(NULL,NULL, ut_buf,pack_len, -1, (char*)&inet_ums_ip,4, (char*)&inet_cli_ip,4);

    // start proxy
    pn->lip = ntohl(inet_ums_ip);//__gg.outer_addr;
    pn->dip = ntohl(inet_cli_ip); //ntohl(ip);
    pn->lvport = ntohs(port);
    pn->dvport = pn->lvport;
    pn->vstream_tout = 60;

    char t[32] = {0};
    inet_ultoa(pn->lip, t);
    printf("lip: %s\n", t);
    inet_ultoa(pn->dip, t);
    printf("dip: %s\n", t);
    printf("lport: %d\n", pn->lvport);
    printf("dport: %d\n", pn->dvport);

    if (start_vs_proxy(pn, (char*)"vp-vsudp-huasan") < 0)
	{
        printf("start proxy failed!!!!\n");
		free(pn);
        return -1;
	}
	free(pn);
   
	return 1;
}

// process data on 12000 port 
static int do_ferry_huasan_vsreq(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
	const static char flg_ccserver[] = "ccserver";
	const static int addr_offset = sizeof(flg_ccserver)-1 + 16 * 8 + 6;
	char *pCcserver = NULL;
	uint32_t ip = 0;
	uint16_t port = 0;
	char *ptr = NULL;

    // client to server  pack size 796
	if ((pCcserver = (char*)memmem(*ut_buf, *pack_len, flg_ccserver, sizeof(flg_ccserver)-1)) == NULL)
		return 1;
    pCcserver += 1;
	if ((pCcserver = (char*)memmem(pCcserver, *pack_len - (pCcserver - *ut_buf), flg_ccserver,sizeof(flg_ccserver)-1)) == NULL)
        return 1;

    ptr = pCcserver + addr_offset;
    //t_disbuf((u_char*)pCcserver, addr_offset + 16 * 4);
	// get dest port
    /*
	memcpy(&port, ptr, sizeof(port));
	// replace port
	memcpy(ptr, &lport, sizeof(lport));
    */
	ptr += sizeof(port);

	// get client ip
	memcpy(&ip, ptr, sizeof(ip));
    // replace client ip to ums ip 
    memreplace_pos(NULL,NULL, ut_buf, pack_len, -1, (char*)(&ip),sizeof(ip), (char*)(&__gg.outer_addr),sizeof(__gg.outer_addr));
    //printf("---- replace client ip to ums ip ------------");

    return 1;
}

int  __huasan_init()
{
    if (load_proxy_config("huasan.conf", 666, PROXY_VIDEO_SERVER, g_cfg_value) < 0)
        printf("load huasan config failed!\n");

	if (load_portpool() < 0)
		return -1;

    // use ip pool
    load_ip_pool();

	return 1;
}

void __huasan_quit()
{
	destroy_portpool();
    //destroy_bind_port();
    free_ip_pool();
    tp_clr_data();
    free_ip_pool();
}

int  __huasan_socket(pvp_uthttp put, int sockfd)
{
    SAI xaddr;

    memset(&xaddr, 0x00, sizeof(xaddr));
    // tms side
    if ((__gg.local_priv_addr & 0xFF) == 1)
    {
        printf("tms ---- dport:%d\n", put->dport);
        xaddr.sin_family = AF_INET;
        //xaddr.sin_addr.s_addr = htonl(put->lip); //inet_addr("10.143.169.229");
        xaddr.sin_addr.s_addr = inet_addr(g_cfg_value[L_AUTHIP]);
        xaddr.sin_port = 0; // ntohs(30000);

        //Setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR);

        if (bind(sockfd, (SA *)&xaddr, sizeof(xaddr)) < 0) 
        {
            printf("__huasan_socket: bind failed!");
            return -1;
        }
    }
    else    // ums side
    {
        printf("ums ---- dport:%d\n", put->dport);
        if (put->dport == 6060)
        {
            ip_pool *idle_ip = get_idle_ip(put);
            if (idle_ip == NULL)
                return -1;

    char t[32] = {0};
    inet_ultoa(idle_ip->lip, t);
    printf("bind lip: %s\n", t);

            xaddr.sin_family = AF_INET;
            xaddr.sin_addr.s_addr = htonl(idle_ip->lip); //INADDR_ANY;
            xaddr.sin_port = htons(6060);
            Setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR);

            if (bind(sockfd, (SA *)&xaddr, sizeof(xaddr)) < 0) 
            {
                printf("__huasan_socket: bind port 6060 failed!\n");
                return -1;
            }
        }
    }

    return 1;
}

int  __huasan_request(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
	const static char flg_main_server[] = "XGMP";
    const static char flg_vsreq[] = "\xbc\xbc\x32\x30";
    const static char flg_vsreq_heart[24] = {0};
 
    // tms side
    if ((__gg.local_priv_addr & 0xFF) == 1)
    {
    }
    else // ums side
    {
    //printf("ums side request -- (len: %d, dport: %d)\n", *pack_len, put->dport);
        if (put->dport == 12000)
        {
        	if (memcmp(*ut_buf, flg_main_server, sizeof(flg_main_server)-1) == 0)
            { // tcp 12000 port
                printf("port:%d, size:%d\n", put->dport, *pack_len);
                if (do_ferry_huasan_vsreq(put, ut_buf, pack_len) < 0)
                    return -1;
            }
        }
        else if (put->dport == 6060)
        {
            if (*pack_len == 240)
            { // udp 6060 port
                const static int user_name_offset = 6 * 16;
                const static int client_addr_offset = 9 * 16 + 8;
                u32 client_ip = -1;
                //u32 inet_ums_ip = -1;
                char flg_user[16] = {0};

                if (memcmp(*ut_buf + sizeof(flg_vsreq)-1, flg_vsreq_heart, sizeof(flg_vsreq_heart)-1) == 0)
                {
                    memcpy(&client_ip, *ut_buf + client_addr_offset, 4);
                    memcpy(flg_user, *ut_buf + user_name_offset, sizeof(flg_user) - 1);
                    if (tp_get_data(flg_user) != NULL)
                        tp_rm_data(flg_user);

                    tp_set_data(flg_user,(char*)&client_ip,4);

                    // replace client ip to ums ip
                    //u32 inet_outer_addr = htonl(__gg.outer_addr);
                    u32 inet_outer_addr = get_inet_ip_from_socket(put->svr_sock);
                    memcpy(*ut_buf + client_addr_offset, (char*)&inet_outer_addr, 4);

                    return 1;
                }
            }
        }
    }

    return 1;
}

int  __huasan_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    const static char flg_vsreq[] = "\xbc\xbc\x32\x30";

    // tms side
    if ((__gg.local_priv_addr & 0xFF) == 1)
    {
    }
    else // ums side
    {
       // printf("reply -- (len: %d, dport: %d)\n", *pack_len, put->dport);
        if (memcmp(*ut_buf, flg_vsreq, sizeof(flg_vsreq)-1) == 0)
        //if (*pack_len == 300)
        {
            if (do_ferry_huasan_6060_vscmd_reply(put, ut_buf, pack_len) < 0)
                return -1;
        }
    }
    
	return 1;
}

int  __huasan_close(pvp_uthttp put, int sockfd)
{
    //ip_pool *idle_ip = get_idle_ip(put);
    ippool_rset_flag(put->cli_addr);
	return 1;
}


