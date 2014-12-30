#include "../vpheader.h"
#include "pm_proxy.h"

const static char FLG_SIP_REG[] = "REGISTER sip:";
const static char FLG_SIP_MEDIA[] = "m=audio ";
const static char FLG_SIP_INVITE[] = "INVITE sip:";
const static char FLG_SIP_REC_ROUTE[] = "Record-Route: <";
const static char FLG_SIP_CONTACT[] = "Contact: ";
const static char RECORD_ROUTE_IP[] = "rec_route_ip";
const static char RECORD_ROUTE_PORT[] = "rec_route_ip";

int start_datang_proxy(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
	const static char FLG_AUDIO[] = "m=audio ";
	const static char FLG_VIDEO[] = "m=video ";
	const static char FLG_MEDIA_IP[] = "IN IP4 ";
	static char PROXY_TYPE[] = "vp-vsudp-1.3";
	const static int tout = 60*60;
	const static int priv_port = __gg.ferry_port;
	int dport = 0;
	u16 lport = 0;
	u16 lport2 = 0;
	char r_src[32] = {0};
	char r_dst[32] = {0};
	char cli_ip[16] = {0};
	char ums_ip[16] = {0};
	char tms_ip[16] = {0};
	char ser_ip[16] = {0};

	char *ptr = NULL;

	if ((ptr = (char*)memmem(*ut_buf, *pack_len, FLG_AUDIO, sizeof(FLG_AUDIO)-1)) != NULL)
	{
		// start audio proxy
		ptr += sizeof(FLG_AUDIO) - 1;
		sscanf(ptr, "%d", &dport);
	
		if ((ptr = strnstr(*ut_buf, FLG_MEDIA_IP, *pack_len, true)) == NULL)
			return 1;
		ptr += sizeof(FLG_MEDIA_IP)-1;
		sscanf(ptr, "%s", cli_ip);
		inet_ultoa(__gg.inner_addr, ums_ip);
		// replace ip
		sprintf(r_src, "%s%s", FLG_MEDIA_IP, cli_ip);
		sprintf(r_dst, "%s%s", FLG_MEDIA_IP, ums_ip);
		strreplace(ut_buf, r_src,r_dst, REPLACE_ALL, pack_len);

		// replace port
		pplist_getidle_port2(&lport, &lport2);
		sprintf(r_src, "%s%d", FLG_AUDIO, dport);
		sprintf(r_dst, "%s%d", FLG_AUDIO, lport);
		strreplace(ut_buf, r_src,r_dst, REPLACE_ONE, pack_len);

		__start_media_proxy(PROXY_TYPE, __gg.inner_addr,put->src_ip, (u16)lport,dport, tout, priv_port);
		__start_media_proxy(PROXY_TYPE, __gg.inner_addr,put->src_ip, (u16)lport2,dport+1, tout, priv_port);
 
		// start video proxy
		if ((ptr = (char*)memmem(*ut_buf, *pack_len, FLG_VIDEO, sizeof(FLG_VIDEO)-1)) != NULL)
		{
			ptr += sizeof(FLG_VIDEO) - 1;
			sscanf(ptr, "%d", &dport);
			pplist_getidle_port2(&lport, &lport2);
			// replace port
			sprintf(r_src, "%s%d", FLG_VIDEO, dport);
			sprintf(r_dst, "%s%d", FLG_VIDEO, lport);
			strreplace(ut_buf, r_src,r_dst, REPLACE_ONE, pack_len);
			__start_media_proxy(PROXY_TYPE, __gg.inner_addr,put->src_ip, lport,dport, tout, priv_port);
			__start_media_proxy(PROXY_TYPE, __gg.inner_addr,put->src_ip, lport2,dport+1, tout, priv_port);
		}

		if (strncmp(*ut_buf, FLG_SIP_INVITE, sizeof(FLG_SIP_INVITE)-1) == 0)
		{
			ptr = *ut_buf + (sizeof(FLG_SIP_INVITE)-1);
			if ((ptr = strnstr(ptr, "@", 32, true)) != NULL)
			{
				ptr += 1;
				sscanf(ptr, "%[^ ]", tms_ip);
				inet_ultoa(__gg.outer_addr, ser_ip);
				//strreplace(ut_buf, tms_ip,ser_ip, REPLACE_ONE, pack_len);
				strreplace_pos(NULL,NULL, ut_buf, tms_ip,ser_ip, 3, pack_len);
			}
		}

		update_content_len(ut_buf, pack_len);
		puts(*ut_buf);
	}

	return 1;
}

/*
int start_datang_media_proxy(pvp_uthttp put, char **ut_buf, u32 *pack_len, u32 lip, u32 dip, int tout)
{
	const static char FLG_AUDIO[] = "m=audio ";
	const static char FLG_VIDEO[] = "m=video ";
	const static char FLG_MEDIA_IP[] = "IN IP4 ";
	static char PROXY_TYPE[] = "vp-vsudp-1.3";
	const static int priv_port = FERRY_PORT_DATANG;
	int dport = 0;
	u16 lport = 0;
	u16 lport2 = 0;
	char r_src[32] = {0};
	char r_dst[32] = {0};
	char dst_ip[16] = {0};
	char local_ip[16] = {0};

	char *ptr = NULL;

	if ((ptr = (char*)memmem(*ut_buf, *pack_len, FLG_AUDIO, sizeof(FLG_AUDIO)-1)) != NULL)
	{
		// start audio proxy
		puts("-------- start porxy 1 --------");
		ptr += sizeof(FLG_AUDIO) - 1;
		sscanf(ptr, "%d", &dport);
	
		if ((ptr = strnstr(*ut_buf, FLG_MEDIA_IP, *pack_len, true)) == NULL)
			return 1;
		ptr += sizeof(FLG_MEDIA_IP)-1;
		sscanf(ptr, "%s", dst_ip);
		inet_ultoa(lip, local_ip);

		puts("-------- start porxy 2 --------");
		// replace ip
		sprintf(r_src, "%s%s", FLG_MEDIA_IP, dst_ip);
		sprintf(r_dst, "%s%s", FLG_MEDIA_IP, local_ip);
		strreplace(ut_buf, r_src,r_dst, REPLACE_ALL, pack_len);
		puts(r_src);
		puts(r_dst);

		// replace port
		pplist_getidle_port2(&lport, &lport2);
		sprintf(r_src, "%s%d", FLG_AUDIO, dport);
		sprintf(r_dst, "%s%d", FLG_AUDIO, lport);
		strreplace(ut_buf, r_src,r_dst, REPLACE_ONE, pack_len);
		puts(r_src);
		puts(r_dst);

		__start_media_proxy(PROXY_TYPE, lip,put->src_ip, (u16)lport,dport, tout, priv_port);
		__start_media_proxy(PROXY_TYPE, lip,put->src_ip, (u16)lport2,dport+1, tout, priv_port);
 
		// start video proxy
		if ((ptr = (char*)memmem(*ut_buf, *pack_len, FLG_VIDEO, sizeof(FLG_VIDEO)-1)) != NULL)
		{
			ptr += sizeof(FLG_VIDEO) - 1;
			sscanf(ptr, "%d", &dport);
			pplist_getidle_port2(&lport, &lport2);
			// replace port
			sprintf(r_src, "%s%d", FLG_VIDEO, dport);
			sprintf(r_dst, "%s%d", FLG_VIDEO, lport);
			strreplace(ut_buf, r_src,r_dst, REPLACE_ONE, pack_len);

		puts(r_src);
		puts(r_dst);
			__start_media_proxy(PROXY_TYPE, lip,dip, lport,dport, tout, priv_port);
			__start_media_proxy(PROXY_TYPE, lip,dip, lport2,dport+1, tout, priv_port);
		}

		update_content_len(ut_buf, pack_len);
		puts("-------------------------------------------------------------");
		puts(*ut_buf);
	}

	return 1;
}
*/

int __datang_init()
{
	g_pm.time_out = 60 * 60 * 24;	
    return load_portpool();
}

void __datang_quit()
{
	destroy_portpool();
    return ;
}

int  __datang_socket(pvp_uthttp put, int sockfd)
{
	/*
	if (put->dport == 5060)
	{
		SAI  xaddr;
        memset(&xaddr, 0x00, sizeof(xaddr));

        xaddr.sin_family = AF_INET;
        xaddr.sin_addr.s_addr = htonl(__gg.inner_addr); //INADDR_ANY;
        xaddr.sin_port = htons(5060);
        Setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR);

        if (bind(sockfd, (SA *)&xaddr, sizeof(xaddr)) < 0) 
        {
            char localip[32] = {0};
            inet_ultoa(__gg.inner_addr, localip);
            loginf_fmt("__datang_socket: bind ip [%s] port [%d] random failed!\n", localip, xaddr.sin_port);
            return -1;
		}
        
	}
	*/
	
	return 1;
}

int __datang_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
	//puts("---------------------- REPLY ---------------------------");
	//puts(*ut_buf);
	/*
	char ip[16] = {0};
	char port[8] = {0};
	char *ptr = NULL;

	if ((ptr = strnstr(*ut_buf, FLG_SIP_CONTACT, *pack_len, true)) != NULL)
	{
		ptr += sizeof(FLG_SIP_CONTACT)-1;
		if ((ptr = strstr(ptr, "@")) == NULL)
			return 1;
		ptr += 1;

	}
	*/

	/*
	if ((ptr = strnstr(*ut_buf, FLG_SIP_REC_ROUTE, *pack_len, true)) != NULL)
	{
		ptr += sizeof(FLG_SIP_REC_ROUTE)-1;
		if ((ptr = strnstr(ptr, ":", *pack_len - (ptr - *ut_buf))) == NULL)
			return 1;
		ptr += 1;
		sscanf(ptr, "%[^:]", ip);
		ptr += strlen(ip)+(sizeof(":")-1);
		sscanf(ptr, "%[^;]", port);
		if (tp_get_data(RECORD_ROUTE_IP) != NULL)
		{
			tp_mod_data(RECORD_ROUTE_IP, ip, sizeof(ip));
			tp_mod_data(RECORD_ROUTE_PORT, port, sizeof(port));
		}
		else
		{
			tp_set_data(RECORD_ROUTE_IP, ip, sizeof(ip));
			tp_set_data(RECORD_ROUTE_PORT, port, sizeof(port));
		}
	}
	*/

    return 1;
}

static int 
do_sip_register(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
	char tmsip[32] = {0};
	char serip[32] = {0};
	char *ptr = NULL;

	if ((ptr = strnstr(*ut_buf, "@", *pack_len, true)) == NULL)
		return 1;
	ptr += 1;
	sscanf(ptr, "%[^ ]", tmsip);
	inet_ultoa(__gg.outer_addr, serip);

	//strreplace(ut_buf, tmsip,serip, REPLACE_ONE, pack_len);
	strreplace_pos(NULL,NULL,ut_buf, tmsip,serip, 3, pack_len);
	/*
	if ((ptr = strnstr(*ut_buf, tmsip, *pack_len, true)) == NULL)
		return 1;
	ptr += 16;
	strreplace_pos(ptr,NULL,ut_buf, tmsip,serip, 1, pack_len);
	*/
	
	return 1;
}

int __datang_request(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
	//char *ptr = NULL;

	if (is_tms())
	{
		/*
		if ((*pack_len == 140) && ((ptr = memmem(*ut_buf, *pack_len, "sip:",sizeof("sip:")-1)) != NULL))
		{
			if ((ptr = memmem(ptr, *pack_len - (ptr - *ut_buf), "@", 1)) == NULL)
				return 1;
		}
		*/
	}
	else
	{
		if (strnstr(*ut_buf, FLG_SIP_MEDIA, *pack_len, true) != NULL)
			return start_datang_proxy(put, ut_buf, pack_len);
			//return start_datang_media_proxy(put, ut_buf, pack_len, __gg.inner_addr,put->src_ip, 40);

		//if (memcmp(*ut_buf, FLG_SIP_REG, sizeof(FLG_SIP_REG)-1) == 0)
			//return do_sip_register(put, ut_buf, pack_len);
		do_sip_register(put, ut_buf, pack_len);
		char cliip[16] = {0};
		char umsip[16] = {0};
		inet_ultoa(put->src_ip, cliip);
		inet_ultoa(__gg.inner_addr, umsip);
		strreplace_pos(NULL,NULL, ut_buf, cliip,umsip, -1, pack_len);
		update_content_len(ut_buf, pack_len);
	}

    return 1;
}

int __datang_close(pvp_uthttp put, int sockfd)
{
    return 1;
}

