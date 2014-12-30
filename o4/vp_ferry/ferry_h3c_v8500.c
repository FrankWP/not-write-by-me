#include "../vpheader.h"
#include "pm_proxy.h"

/*
 * ShanXi JinCheng huasan platform
 */

static char g_ums_ip[16] = {0};
static char g_tms_ip[16] = {0};

int  __h3c_v8500_init()
{
	if (load_portpool() < 0)
	{
		logdbg_out("load port pool failed!");
		return -1;
	}
	if (init_bind_port(6001, 1000) < 0)
	{
		logdbg_out("get bind port failed!");
		return -1;
	}

	inet_ultoa(__gg.inner_addr, g_tms_ip);
	inet_ultoa(__gg.outer_addr, g_ums_ip);

	return 1;
}

void __h3c_v8500_quit()
{
	destroy_portpool();
	destroy_bind_port();
}

int  __h3c_v8500_socket(pvp_uthttp put, int sockfd)
{
    SAI xaddr;
	u32 lip = __gg.outer_addr;
	u16 port = 0;

	if (is_tms())
	{
		memset(&xaddr, 0x00, sizeof(xaddr));
		xaddr.sin_family = AF_INET;
		xaddr.sin_addr.s_addr = INADDR_ANY;
		xaddr.sin_port = htons(put->src_port);

		if (bind(sockfd, (SA *)&xaddr, sizeof(xaddr)) < 0)
		{
			logdbg_out("bind port failed!");
			return -1;
		}
	}
	else // is ums
	{
		if (put->dport == 5060)
		{
			puts("dport is 5060");

			if ((port = get_idle_bind_port(NUM_ANY)) <= 0)
			{
				logdbg_out("get idle bind port failed!");
				return -1;
			}

			memset(&xaddr, 0x00, sizeof(xaddr));
			xaddr.sin_family = AF_INET;
			xaddr.sin_addr.s_addr = htonl(lip);	// INADDR_ANY;
			xaddr.sin_port = htons(port);

			if (bind(sockfd, (SA *)&xaddr, sizeof(xaddr)) < 0)
			{
				logdbg_out("bind port failed!");
				return -1;
			}
		}
	}

	return 1;
}

static int
jincheng_h3c_rtsp_replace_outeraddr(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
	char cli_ip[16] = {0};
	//char ser_ip[16] = {0};
	char r_src[64] = {0};
	char r_dst[64] = {0};
	u16 sender_port = get_inet_port_from_socket(put->svr_sock);
	sender_port = ntohs(sender_port);

	inet_ultoa(put->src_ip, cli_ip);

	sprintf(r_src, "%s:%d", cli_ip, put->src_port);
	sprintf(r_dst, "%s:%d", g_ums_ip, sender_port);
	strreplace_pos(NULL,NULL, ut_buf, r_src,r_dst, -1, pack_len);
	puts("client address");
	printf("r_src:%s\n", r_src);
	printf("r_dst:%s\n", r_dst);

	inet_ultoa(put->dip, r_dst);
	strreplace_pos(NULL,NULL, ut_buf, g_tms_ip,r_dst, -1, pack_len);
	//sprintf(r_src, "%s", inet_ultoa(put->dip, ser_ip))

	update_content_len(ut_buf, pack_len);

	return 1;
}

static int 
jincheng_h3c_rtsp_request(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
	const static char FLG_INVITE[] = "INVITE";
	const static char FLG_SIP_IP[] = "IN IP4 ";
	const static char FLG_SIP_PORT_AUDIO[] = "m=audio ";
	const static char FLG_SIP_PORT_VIDEO[] = "m=video ";
	u16 laport = 0;
	u16 lvport = 0;
	char cli_ip[32] = {0};
	//char cli_aport[32] = {0};	// audio port
	//char cli_vport[32] = {0};	// video port
	u32 cli_aport = 0;
	u32 cli_vport = 0;
	char r_src[64] = {0};
	char r_dst[64] = {0};
	char ums_ip[16] = {0};
	char *ptr = NULL;
	//int offset = 0;

	// make sure that the data is sip protocol
	if (memcmp(*ut_buf, "SIP/", 4) != 0)
		return 1;
	// make sure that the data is invite action
	if ((ptr = strnstr(*ut_buf, FLG_INVITE, *pack_len, true)) == NULL)
		return 1;
	if ((ptr = strnstr(ptr, FLG_SIP_IP, *pack_len - (ptr - *ut_buf), true)) == NULL)
		return 1;
	// get client ip and ums ip
	inet_ultoa(__gg.outer_addr, ums_ip);
	ptr += sizeof(FLG_SIP_IP)-1;
	sscanf(ptr, "%[0-9.]", cli_ip);
	
	// get audio port
	if ((ptr = strnstr(ptr, FLG_SIP_PORT_AUDIO, *pack_len - (ptr - *ut_buf), true)) == NULL)
		return 1;
	ptr += sizeof(FLG_SIP_PORT_AUDIO)-1;
	//sscanf(ptr, "%[0-9]", cli_aport);
	sscanf(ptr, "%d", &cli_aport);

	// get video port
	if ((ptr = strnstr(ptr, FLG_SIP_PORT_VIDEO, *pack_len - (ptr - *ut_buf), true)) == NULL)
		return 1;
	ptr += sizeof(FLG_SIP_PORT_VIDEO)-1;
	//sscanf(ptr, "%[0-9]", cli_vport);
	sscanf(ptr, "%d", &cli_vport);
	
	// replace client ip to ums ip
	sprintf(r_src, "%s%s", FLG_SIP_IP, cli_ip);
	sprintf(r_dst, "%s%s", FLG_SIP_IP, g_ums_ip);
	strreplace_pos(NULL,NULL, ut_buf, r_src,r_dst, -1, pack_len);

	// replace audio port
	if ((laport = pplist_getidle_port()) <= 0)
	{
		logdbg_out("ferry shanxi jincheng h3c: get idle port failed!");
		return -1;
	}
	//sprintf(r_src, "%s%s", FLG_SIP_PORT_AUDIO, cli_aport);
	sprintf(r_src, "%s%d", FLG_SIP_PORT_AUDIO, cli_aport);
	sprintf(r_dst, "%s%d", FLG_SIP_PORT_AUDIO, laport);
	strreplace_pos(NULL,NULL, ut_buf, r_src,r_dst, -1, pack_len);

	// replace video port
	if (cli_aport == cli_vport)
	{
		lvport = laport;
	}
	else
	{
		if ((lvport = pplist_getidle_port()) <= 0)
		{
			logdbg_out("ferry shanxi jincheng h3c: get idle port failed!");
			return -1;
		}
	}
	//sprintf(r_src, "%s%s", FLG_SIP_PORT_VIDEO, cli_vport);
	sprintf(r_src, "%s%d", FLG_SIP_PORT_VIDEO, cli_vport);
	sprintf(r_dst, "%s%d", FLG_SIP_PORT_VIDEO, lvport);
	strreplace_pos(NULL,NULL, ut_buf, r_src,r_dst, -1, pack_len);
	
	update_content_len(ut_buf, pack_len);

	// start proxy
    run_vs_udp_proxy(__gg.outer_addr, inet_atoul(cli_ip), laport, cli_aport, 0, put->session_tout, __gg.ferry_port);
	if (cli_aport != cli_vport)
        run_vs_udp_proxy(__gg.outer_addr, inet_atoul(cli_ip), lvport, cli_vport, 0, put->session_tout, __gg.ferry_port);

	return 1;
}

int jincheng_h3c_record_rtsp_request(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
	const static char FLG_RCV_IP[] = "destination=";
	const static char FLG_RCV_PORT[] = "client_port=";
	
	char cli_ip[16] = {0};
	char cli_port[16] = {0};
	char r_src[64] = {0};
	char r_dst[64] = {0};
	char *ptr = NULL;
	u16 lport = 0;

	if ((ptr = (char*)memmem(*ut_buf, *pack_len, FLG_RCV_IP, sizeof(FLG_RCV_IP)-1)) == NULL)
		return 1;
	ptr += sizeof(FLG_RCV_IP)-1;
	sscanf(ptr, "%[^;]", cli_ip);
	if ((ptr = (char*)memmem(ptr, *pack_len - (ptr - *ut_buf), FLG_RCV_PORT, sizeof(FLG_RCV_PORT)-1)) == NULL)
		return 1;
	ptr += sizeof(FLG_RCV_PORT)-1;
	sscanf(ptr, "%[^-]", cli_port);

	// get an idle port from pool
	if ((lport = pplist_getidle_port()) <= 0)
	{
		logdbg_out("jincheng_h3c_record_rtsp_request: get idle port failed!");
		return -1;
	}
	
	// replace client ip to ums ip
	sprintf(r_src, "%s%s", FLG_RCV_IP, cli_ip);
	sprintf(r_dst, "%s%s", FLG_RCV_IP, g_ums_ip);
	strreplace_pos(NULL,NULL, ut_buf, r_src,r_dst, -1, pack_len);

	// replace client port to ums port
	sprintf(r_src, "%s%s", FLG_RCV_PORT, cli_port);
	sprintf(r_dst, "%s%d", FLG_RCV_PORT, lport);
	strreplace_pos(NULL,NULL, ut_buf, r_src,r_dst, -1, pack_len);

	printf("start record proxy\n");
	printf("laddr: %s:%d\n", g_ums_ip, lport);
	printf("daddr: %s:%s\n", cli_ip, cli_port);
	// start proxy
    run_vs_udp_proxy(__gg.outer_addr, inet_atoul(cli_ip), lport, atoi(cli_port), 0, put->session_tout, __gg.ferry_port);

	return 1;
}

int __h3c_v8500_recv(pvp_uthttp put, char *utbuf, int *pack_len, int directon)
{
	const static char FLG_RTSP_SETUP[] = "SETUP rtsp://";
	char *ptr = NULL;

	if (directon == DO_REPLY)
		return 1;

	if (put->dport == 554)
	{
		puts("---- dport is 554 -------");
		if (memcmp(utbuf, FLG_RTSP_SETUP, sizeof(FLG_RTSP_SETUP)-1) == 0)
		{
			oss_malloc(&ptr, *pack_len);
			memcpy(ptr, utbuf, *pack_len);

			jincheng_h3c_record_rtsp_request(put, &ptr, (u32*)pack_len);

			memcpy(utbuf, ptr, *pack_len);
			oss_free(&ptr);
		}
	}

	return 1;
}

int  __h3c_v8500_request(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
	if (put->dport == 5060)
	{
		/*
		puts("----  SIP request ------");
		puts(*ut_buf);
		*/
		jincheng_h3c_rtsp_replace_outeraddr(put, ut_buf, pack_len);
		jincheng_h3c_rtsp_request(put, ut_buf, pack_len);
		/*
		puts("------------------------------------------------------");
		puts(*ut_buf);
		puts("---- SIP request end ------");
		*/
	}

	return 1;
}

int jincheng_h3c_reply_ack(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
	const static char FLG_SIP_IP[] = "IN IP4 ";
	char vs_ip[16] = {0};
	char cli_ip[16] = {0};
	char r_src[64] = {0};
	char r_dst[64] = {0};
	u16 sender_port = 0;
	char *ptr = NULL;
	
	puts("----  SIP ACK reply ------");
	puts(*ut_buf);

	get_inet_port_from_socket(put->svr_sock);
	sender_port = ntohs(sender_port);

	inet_ultoa(put->src_ip, cli_ip);

	sprintf(r_src, "%s:%d", g_ums_ip, sender_port);
	sprintf(r_dst, "%s:%d", cli_ip, put->src_port);
	strreplace_pos(NULL,NULL, ut_buf, r_src,r_dst, -1, pack_len);

	if ((ptr = (char*)memmem(*ut_buf, *pack_len, FLG_SIP_IP, sizeof(FLG_SIP_IP)-1)) == NULL)
		return 1;
	ptr += sizeof(FLG_SIP_IP)-1;
	sscanf(ptr, "%[0-9.]", vs_ip);

	sprintf(r_src, "%s%s", FLG_SIP_IP, vs_ip);
	sprintf(r_dst, "%s%s", FLG_SIP_IP, g_tms_ip);
	strreplace_pos(NULL,NULL, ut_buf, r_src,r_dst, -1, pack_len);

	update_content_len(ut_buf, pack_len);

	return 1;
}

int  __h3c_v8500_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
	const static char FLG_ACK[] = "ACK sip:";

	if (g_pm.proxy_type == P_TCP_PROXY)
	{
		return 1;
	}
	else 
	{
		if (memcmp(*ut_buf, FLG_ACK, sizeof(FLG_ACK)-1) == 0)
			return jincheng_h3c_reply_ack(put, ut_buf, pack_len);
	}
	
	return 1;
}

int  __h3c_v8500_close(pvp_uthttp put, int sockfd)
{
	u16 sender_port = 0;

	if (g_pm.proxy_type == P_TCP_PROXY)
	{
		return 1;
	}
	else
	{
		if (put->dport == 5060)
		{
			sender_port = get_inet_port_from_socket(sockfd);
			set_idle_bind_port(ntohs(sender_port));
			printf("free bind port:%d\n", ntohs(sender_port));
		}
	}
	
	return 1;
}

