#include "common.h"
#include "vp_uthttp.h"
#include "vp_thread_setting.h"
#include "pool_port.h"
#include "thread_private_data.h"
#include "vp_multi_protol.h"

#define set_init_value(tl, hl, bl) do { \
	tl = 0; \
	hl = 0; \
	bl = 0; \
} while (0)

#define destroy_value(tl, hl, bl, reqst) do { \
	set_init_value(tl, hl, bl); \
	oss_free(reqst); \
} while (0)

/*
   int count_flow(long bytes)
   {
   const static char FLOW_VAL[] = "flow_val";
   const static char FLOW_TIME[] = "flow_tm";
   const static int interval = 5;
   tdata *pflow = NULL;
   tdata *ptime = NULL;
   time_t tnow = time(0);
   time_t told = 0;
   long len = 0;

   if ((ptime = tp_get_data(FLOW_TIME)) == NULL)
   {
   tp_set_data(FLOW_TIME, (char*)&tnow, sizeof(tnow));
//logdbg_fmt("tnow: %ld", tnow);
told = tnow;
}
else 
{
memcpy(&told, ptime->data, ptime->len);
}

if ((pflow = tp_get_data(FLOW_VAL)) == NULL)
{
tp_set_data(FLOW_VAL, (char*)&len, sizeof(len));
}
else
{
memcpy(&len, pflow->data, pflow->len);
}

len += bytes;
tp_mod_data(FLOW_VAL, (char*)&len, sizeof(len));

if (tnow - told > interval)
{
logdbg_fmt("rate: %ld B/s (%ld kB/s)", len/interval, len/interval/1024);
len = 0;
tp_mod_data(FLOW_VAL, (char*)&len, sizeof(len));
tp_mod_data(FLOW_TIME, (char*)&tnow, sizeof(tnow));
}

return len;
}
*/

/*
 *  @ return:  -1--error; 0--have data read; 1--finish read
 *  @ side:    the operate of client request or reply
 *  @ careful: do not use strlen(buf), because have binary data
 */
static int tcp_data_deal(pvp_uthtrans prun,
		int rsock, int ssock,
		char **reqst, u32 *tl,
		u32 *hl, u32 *bl,
		int *chk, bool enable_chunked, int side, int *frm_cnt, bool is_ferry)
{
	int  ret = -1;
	int  retval = 1;
	char data_buf[BUF_SIZE] = {0};
	char *pkg = NULL;
	u32 len_pkg = 0;
	tset_arg *targ = NULL;
    DO_RECEIVER_T do_reply_receiver = NULL;
    DO_RECEIVER_T do_request_receiver = NULL;

    if(is_ferry)
    {
        if (tset_is_flg_set(&prun->vphttp.tset, TSET_USE_PROTO_UMS_CLIENT))
        {
            if ((targ = tset_fetch_arg(&prun->vphttp.tset, TSET_USE_PROTO_UMS_CLIENT)) == NULL)
            {
                logwar_out("TSET_USE_PROTO_UMS_CLIENT: get thread arg failed!");
                return -1;
            }

            do_request_receiver	= request_receiver_multiprotocal(targ->n);
            //loginf_out("ums use do_request_receiver: TSET_USE_PROTO_UMS_CLIENT");
        }

        if (tset_is_flg_set(&prun->vphttp.tset, TSET_USE_PROTO_UMS_SERVER))
        {
            if ((targ = tset_fetch_arg(&prun->vphttp.tset, TSET_USE_PROTO_UMS_SERVER)) == NULL)
            {
                logwar_out("TSET_USE_PROTO_UMS_SERVER: get thread arg failed!");
                return -1;
            }
            do_reply_receiver = reply_receiver_multiprotocal(targ->n);
            //loginf_out("ums use do_reply_receiver: TSET_USE_PROTO_UMS_SERVER");
        }

    }
    else
    {

        if (tset_is_flg_set(&prun->vphttp.tset, TSET_USE_PROTO_TMS_CLIENT))
        {
            if ((targ = tset_fetch_arg(&prun->vphttp.tset, TSET_USE_PROTO_TMS_CLIENT)) == NULL)
            {
                logwar_out("TSET_USE_PROTO_TMS_CLIENT: get thread arg failed!");
                return -1;
            }
            do_request_receiver = request_receiver_multiprotocal(targ->n);
            //loginf_out("tms use do_request_receiver: TSET_USE_PROTO_TMS_CLIENT");
        }

        if (tset_is_flg_set(&prun->vphttp.tset, TSET_USE_PROTO_TMS_SERVER))
        {
            if ((targ = tset_fetch_arg(&prun->vphttp.tset, TSET_USE_PROTO_TMS_SERVER)) == NULL)
            {
                logwar_out("TSET_USE_PROTO_TMS_SERVER: get thread arg failed!");
                return -1;
            }
            do_reply_receiver = reply_receiver_multiprotocal(targ->n);
            //loginf_out("tms use do_reply_receiver: TSET_USE_PROTO_TMS_SERVER");
        }
    }

	if (side == DO_REQST) 
	{
		if ( do_request_receiver != NULL)
		{
            puts("Recv Single Request");

			ret = do_request_receiver(rsock, (void*)prun, &pkg, &len_pkg, NULL, NULL);
			if (ret <= 0)
			{
				oss_free(&pkg);
				return -1;
			}
            ret = len_pkg;
			memcpy(data_buf, pkg, len_pkg);
			oss_free(&pkg);
		}
		else
		{
			if ((ret = Recv(rsock, data_buf, BUF_SIZE, 0)) <= 0)
			{
				return -1;
			}

            puts("***************Recvdata in requst*********************:");
            t_disbuf(data_buf, ret);
		}
	}
	else 
	{
		if ( do_reply_receiver != NULL)
		{
            puts("Recv Single Reply");

			ret = do_reply_receiver(rsock, (void*)prun, &pkg, &len_pkg, NULL, NULL);
			if (ret <= 0)
			{
				oss_free(&pkg);
				return -1;
			}
            ret = len_pkg;
			memcpy(data_buf, pkg, len_pkg);
			oss_free(&pkg);
		}
		else
		{
			if ((ret = Recv(rsock, data_buf, BUF_SIZE, 0)) <= 0)
			{
				return -1;
			}
            
            puts("***************Recvdata in reply*********************");
            t_disbuf(data_buf, ret);
		}
	}

	if (prun->do_recv) 
	{
		if (prun->do_recv(&prun->vphttp, data_buf, &ret, side) < 0)
		{
			return -1;
		}
	}

	if (prun->vphttp.data_cache == N_CACHE)
	{
		ret = Send(ssock, data_buf, ret, MSG_NOSIGNAL);

        printf("***************no cache send: %d*********************", ret);
        t_disbuf(data_buf, ret);

		return ret;
	}

	if (tset_is_flg_set(&prun->vphttp.tset, TSET_ENABLE_CHUNKED))
		enable_chunked = true;
	else
		enable_chunked = false;

	if (enable_chunked)
	{
		if (http_chunked_check(data_buf, ret) == 0 || *chk == 1) {
			if ((retval = http_chunked_mode(reqst, data_buf, ret, tl, chk)) <= 0)
				return retval;
			goto __send;
		}
		if ((retval = http_general_mode(reqst, data_buf, ret, tl, hl, bl)) <= 0)
			return retval;
	}
	else
	{
		oss_malloc(reqst, ret + 1);
		memcpy(*reqst, data_buf, ret);
		*tl = ret;
	}

__send:
	(*reqst)[*tl] = 0x00;

	if (side == DO_REQST && prun->do_request)
		retval = prun->do_request(&prun->vphttp, reqst, tl);
	else if (side == DO_REPLY && prun->do_reply)
		retval = prun->do_reply(&prun->vphttp, reqst, tl);

	if (retval <= 0) {
		destroy_value(*tl, *hl, *bl, reqst);
		return 0;
	}

#if 0
	if ((frm_cnt != NULL) && (side == DO_REPLY) && g_frmp.frame_enable)
	{
		if (frame_run_count(frm_cnt))
		{
			if ( ! g_frmp.frame_modify_flg)
			{
				destroy_value(*tl, *hl, *bl, reqst);
				return 0;
			}
			else if (Send(ssock, *reqst, *tl, 0) < 0)
			{
				destroy_value(*tl, *hl, *bl, reqst);
				return -1;
			}
		}
	}
#endif
	ret = 1;

    puts("*************** has cache send *********************");
    t_disbuf(*reqst, *tl);
	if (Send(ssock, *reqst, *tl, MSG_NOSIGNAL) < 0)
		ret = -1;

	destroy_value(*tl, *hl, *bl, reqst);
	//oss_free(&data_buf);
	return ret;
}

static void * ___run_tcp_proxy(void *arg, bool is_ferry)
{
	u32    rt = 0;
	u32    blen = 0;
	u32    hlen = 0;
	int    chunk = 0;
	char * reqst = NULL;
	int    maxfd = -1;
	int    ret = -1;
	int    req_ret = -1;
	int    rep_ret = -1;
	int    cli_sock = -1;
	int    svr_sock = -1;
	SAI    svr_addr;
	fd_set rfds;
	//fd_set errfds;
	struct timeval tv;
	int    frm_cnt = 1;
	bool   enable_chunked = false;

	pvp_uthtrans prun = (pvp_uthtrans)arg;
	if (prun == NULL)
		goto __session_end;

	if ((svr_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		goto __session_end;

	if (prun->do_socket) {
		if (prun->do_socket(&prun->vphttp, svr_sock) < 0)
			goto __session_end;
	}

	init_sockaddr(&svr_addr, prun->vphttp.dip, prun->vphttp.dport);

	if (is_ferry)
    {
		ret = Connect(svr_sock, (struct sockaddr *)&svr_addr, sizeof(svr_addr), 5);
    }
	else
    {
        ret = tcp_connect(svr_sock, 5, prun);
    }
	if (ret < 0) 
	{
		close_sock(&prun->vphttp.cli_sock);
		goto __session_end;
	}

	prun->vphttp.svr_sock = svr_sock;
	cli_sock = prun->vphttp.cli_sock;
	maxfd = svr_sock > cli_sock ? svr_sock : cli_sock;

	if (Setsockopt(svr_sock, SOL_SOCKET, SO_REUSEADDR) < 0
			|| Setsockopt(cli_sock, SOL_SOCKET, SO_REUSEADDR) < 0)
		goto __session_end;

	if (tset_is_flg_set(&prun->vphttp.tset, TSET_ENABLE_CHUNKED))
		enable_chunked = true;

	for(;;) {
		FD_ZERO(&rfds);
		FD_SET(svr_sock, &rfds);
		FD_SET(cli_sock, &rfds);
		/*
		   FD_ZERO(&errfds);
		   FD_SET(svr_sock, &errfds);
		   FD_SET(cli_sock, &errfds);
		   */

		tv.tv_sec = prun->vphttp.session_tout;
		tv.tv_usec = 0;

		//ret = Select(maxfd, &rfds, NULL, &errfds, &tv);
		ret = Select(maxfd, &rfds, NULL, NULL, &tv);
		if (ret < 0)
			break ;
		if (ret == 0)
			continue;
		/*
		   if (FD_ISSET(cli_sock, &errfds) ||
		   FD_ISSET(svr_sock, &errfds))
		   {
		   puts("select error occured!");
		   break;
		   }
		   */

		req_ret = 1;
		rep_ret = 1;
		if (FD_ISSET(cli_sock, &rfds)) 
        {
			req_ret = tcp_data_deal(prun, cli_sock, svr_sock,
					&reqst, &rt, &hlen, &blen, &chunk, enable_chunked, DO_REQST, NULL, is_ferry);
		}

		if (FD_ISSET(svr_sock, &rfds))
        {
			rep_ret = tcp_data_deal(prun, svr_sock, cli_sock,
					&reqst, &rt, &hlen, &blen, &chunk, enable_chunked, DO_REPLY, &frm_cnt,is_ferry);
		}
		if ((req_ret == -1) || (rep_ret == -1))
			break;
	}

__session_end:
	if (prun != NULL) {
		if (prun->do_close != NULL)
			prun->do_close(&prun->vphttp, svr_sock);
	}

	close_sock(&cli_sock);
	close_sock(&svr_sock);
	oss_free(&prun);
	oss_free(&reqst);
	return NULL;
}

static void * run_ferry_tcp_proxy(void *arg)
{
	return ___run_tcp_proxy(arg, true);
}

static void * run_tcp_proxy(void * arg)
{
	return ___run_tcp_proxy(arg, false);
}

static int ferry_accept(int fd, SAI *addr, pvp_uthtrans puthtrans)
{
	return tcp_accept(fd, addr, puthtrans);
}

static int tms_accept(int fd, SAI *addr, pvp_uthtrans puthtrans)
{
	/* do nothing with dip, dport*/
	static socklen_t socklen = sizeof(SAI);
	return Accept(fd, (SA*)addr, &socklen);
}

static void * ___start_tcp_proxy(void * arg, bool is_ferry)
{
	int       lsn_sock = -1;
	int       cli_thread;
	int       cli_sock = -1;
	SAI       cli_addr;
	SAI       lsn_addr;
	pthread_t thread_id;
	tfunc_runproxy thread_run = NULL;
	int (*proxy_accept)(int, SAI*, pvp_uthtrans) = NULL;
	struct timeval tout;
	tset_arg *ts_times = NULL;
	tset_arg *ts_tout = NULL;
	int err_times = 5;

	thread_run = is_ferry ? run_ferry_tcp_proxy : run_tcp_proxy;
	proxy_accept = is_ferry ? ferry_accept : tms_accept;

	pvp_uthtrans pstart = (pvp_uthtrans)arg;
	if (pstart == NULL)
		return NULL;

	if ((lsn_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		goto __end;

	if (Setsockopt(lsn_sock, SOL_SOCKET, SO_REUSEADDR) < 0)
		goto __end;

	/* set client and server address */
	init_sockaddr(&lsn_addr, pstart->vphttp.lip, pstart->vphttp.lport);

	if (Bind(lsn_sock, lsn_addr, sizeof(lsn_addr)) < 0)
		goto __end;

	listen(lsn_sock, 200);

	ts_times = tset_fetch_arg(&pstart->vphttp.tset, TSET_CONN_TIMES);
	ts_tout = tset_fetch_arg(&pstart->vphttp.tset, TSET_LSN_TOUT_EXIT);
	if (ts_tout != NULL)
	{
		tout.tv_sec = ts_tout->n;  // Seconds Timeout
		tout.tv_usec = 0;  
		if (setsockopt(lsn_sock, SOL_SOCKET, SO_RCVTIMEO, &tout,sizeof(struct timeval)) < 0)
		{
			//logdbg_out("set listen recv timeout failed!");
			goto __end;
		}
	}

	for (;;) {
		if ((ts_times != NULL) && ((int64_t)(--ts_times->n) < 0))
			break;
		memset(&cli_addr, 0x00, sizeof(cli_addr));
		cli_sock = proxy_accept(lsn_sock, &cli_addr, pstart);
		if (cli_sock < 0)
		{
            loginf_out("proxy_accept error!");
			usleep(1000);
			--err_times;
			if (err_times == 0)
				break;
			continue;
			//break ;
		}
		else
		{
			err_times = 5;
		}
#if 0
		if (ip_can_through(&prio_ip_flg, pstart->vphttp.cliip, &prio_ip_tm) == -1)
		{
			close_sock(&cli_sock);
			continue;
		}
		if (prio_ip_flg == CLOSE)
		{
			close_sock(&cli_sock);
			continue;
		}
#endif

		pvp_uthtrans prun = (pvp_uthtrans)malloc(sizeof(vp_uthtrans));
		if (prun == NULL)
			break;

		memcpy(prun, pstart, sizeof(vp_uthtrans));
		prun->vphttp.cli_sock = cli_sock;
		if ( ! is_ferry)
		{
			prun->vphttp.src_ip = ntohl(cli_addr.sin_addr.s_addr);
			prun->vphttp.src_port = ntohs(cli_addr.sin_port);
		}

		memcpy(&prun->vphttp.cli_addr, &cli_addr, sizeof(cli_addr));

		cli_thread = pthread_create(&thread_id, NULL, thread_run, (void *)prun);
		if (cli_thread == 0)
			pthread_detach(thread_id);
	}

__end:
	if (tset_is_flg_set(&(pstart->vphttp.tset), TSET_PPORT_FREE))
	{
		pplist_set_flag_port(pstart->vphttp.lport);
	}
	close_sock(&lsn_sock);
	//tset_clear(&pstart->vphttp.tset);
	oss_free(&pstart);
	return NULL;
}

static void * start_tcp_proxy(void * arg)
{
	return ___start_tcp_proxy(arg, false);
}

static void * start_ferry_tcp_proxy(void * arg)
{
	return ___start_tcp_proxy(arg, true);
}

static int __load_tcp_proxy(pvp_uthtrans pt, int t_state, bool is_ferry)
{
	int        tret = -1;
	pthread_t  tid;
	tfunc_runproxy start_proxy = NULL;

	start_proxy = is_ferry ? start_ferry_tcp_proxy : start_tcp_proxy;

    puts("__load_tdp_proxy");
	tret = pthread_create(&tid, NULL, start_proxy, (void *)pt);
	if (tret != 0)
		return -1;

	if (t_state == T_WAITING)
		pthread_join(tid, NULL);
	if (t_state == T_DETACH)
		pthread_detach(tid);

	return 1;
}

int load_tcp_proxy(pvp_uthtrans pt, int t_state)
{   
	return __load_tcp_proxy(pt, t_state, false);
}

int load_ferry_tcp_proxy(pvp_uthtrans pt, int t_state)
{
	return __load_tcp_proxy(pt, t_state, true);
}

