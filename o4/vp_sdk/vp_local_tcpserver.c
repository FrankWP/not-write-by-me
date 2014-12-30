#include "common.h"
#include "vp_uthttp.h"
#include "vp_thread_setting.h"
#include "pool_port.h"
#include "vp_local_tcpserver.h"

static void * __run_local_tcp_server(void *arg)
{
	char buf[BUF_SIZE] = {0};
    char * reqst = NULL;
	//u32 buf_len = BUF_SIZE;
	int result = LSERVER_RECVNEXT;
	int ret = -1;
	u32 ulen = 0;

    vp_uthtrans trans;
    if (arg == NULL)
		return NULL;
	memcpy(&trans, arg, sizeof(vp_uthtrans));
    oss_free(&arg);
	
	printf("new client and new thread: %d\n", trans.vphttp.cli_sock);

    /*
	if (oss_malloc(&reqst, BUF_SIZE) < 0)
	{
		logdbg_out("Local server: malloc failed!");
		return NULL;
	}
    */

	while (1)
	{
		//ret = Recv(trans.vphttp.cli_sock, reqst, buf_len, 0);
		ret = Recv(trans.vphttp.cli_sock, buf, BUF_SIZE, 0);
		if (ret <= 0)
		{
			//logdbg_fmt("Local server: socket %d. %s(ret:%d, buf_len:%d)!", trans.vphttp.cli_sock, strerror(errno), ret, buf_len);
            if (ret < 0)
			    logdbg_fmt("Local server: socket %d. %s(ret:%d)!", trans.vphttp.cli_sock, strerror(errno), ret);
			break;
		}

		if (trans.do_request != NULL)
		{
            if (oss_malloc(&reqst, ret) < 0)
            {
                logdbg_out("Local server: malloc failed!");
                return NULL;
            }
            memcpy(reqst, buf, ret);

            ulen = ret;
			result = trans.do_request(&trans.vphttp, &reqst, &ulen);
			if ((reqst == NULL) || (ulen == 0))
			{
				logdbg_fmt("Local server: Invalid data after do_request !(socket:%d, ptr:%p, len:%u", trans.vphttp.cli_sock, reqst, ulen);
				break;
			}

		}

		/*
		if (result == LSERVER_REPLY) 
		{
			if (Send(trans.vphttp.cli_sock, reqst, ulen, MSG_NOSIGNAL) <= 0)
			{
				logdbg_fmt("Local server: Send data back failed! (socket:%d)", trans.vphttp.cli_sock);
				break;
			}
		}
		*/
		if (result == LSERVER_ENDSESSION)
			break;
		else if (result == LSERVER_RECVNEXT)
			continue;
    }
    close_sock(&trans.vphttp.cli_sock);
    oss_free(&reqst);

    return NULL;
}

static void * __start_local_tcpserver(void * arg)
{
    int       lsn_sock = -1;
    int       cli_sock = -1;
    int       cli_thread;
    SAI       lsn_addr;
    SAI       cli_addr;
    pthread_t thread_id;
	struct timeval tout;
    tset_arg *ts_times = NULL;
    tset_arg *ts_tout = NULL;
    static socklen_t socklen = sizeof(SAI);
	vp_uthtrans trans;
	char buf[32] = {0};
	pvp_uthtrans prun = NULL;

	if (arg == NULL)
		return NULL;
	memcpy(&trans, arg, sizeof(vp_uthtrans));
	oss_free(&arg);

    if ((lsn_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
	{
		logdbg_out("Start local tcp proxy: create socket failed!");
		return NULL;
	}

    if (Setsockopt(lsn_sock, SOL_SOCKET, SO_REUSEADDR) < 0)
	{
		logdbg_out("Start local tcp proxy: set socket reuse failed!");
		close(lsn_sock);
		return NULL;
	}

	// set listen address
    init_sockaddr(&lsn_addr, trans.vphttp.lip, trans.vphttp.lport);
    if (Bind(lsn_sock, lsn_addr, sizeof(lsn_addr)) < 0)
	{
		logdbg_fmt("Start local tcp proxy: bind socket to %s:%d failed!", inet_ultoa(trans.vphttp.lip, buf), trans.vphttp.lport);
		close(lsn_sock);
		return NULL;
	}

    if (listen(lsn_sock, 200) < 0)
	{
		logdbg_fmt("Start local tcp proxy: listen %s:%d failed!", inet_ultoa(trans.vphttp.lip, buf), trans.vphttp.lport);
		close(lsn_sock);
		return NULL;
	}

    ts_times = tset_fetch_arg(&trans.vphttp.tset, TSET_CONN_TIMES);
    ts_tout = tset_fetch_arg(&trans.vphttp.tset, TSET_LSN_TOUT_EXIT);
    if (ts_tout != NULL)
    {
		tout.tv_sec = ts_tout->n;  // Seconds Timeout
		tout.tv_usec = 0;  
		if (setsockopt(lsn_sock, SOL_SOCKET, SO_RCVTIMEO, &tout,sizeof(struct timeval)) < 0)
        {
			logdbg_out("Start local tcp proxy: set listen timeout failed!");
			close(lsn_sock);
			return NULL;
        }
		logdbg_fmt("Start local tcp proxy: set listen timeout success (%d seconds)!", (int)ts_tout->n);
    }

    for (;;) {
        if ((ts_times != NULL) && ((int64_t)(--ts_times->n) < 0))
            break;
        memset(&cli_addr, 0x00, sizeof(cli_addr));
		cli_sock = Accept(lsn_sock, (struct sockaddr*)&cli_addr, &socklen);
		printf("new connection: %d\n", cli_sock);
        if (cli_sock <= 0)
		{
			logdbg_out("Local server: accept error!");
            break ;
		}
		// set timeout of new session 
		if (set_sock_timeout(cli_sock, trans.vphttp.session_tout * 10, trans.vphttp.session_tout * 10) < 0)
		{
			logdbg_out("Local server: set session timeout failed!");
			close_sock(&cli_sock);
			break;
		}

        if (oss_malloc(&prun, sizeof(vp_uthtrans)) < 0)
		{
			logdbg_out("Local server: malloc thread argument failed!");
			close_sock(&cli_sock);
            break;
		}

        memcpy(prun, &trans, sizeof(vp_uthtrans));
        prun->vphttp.cli_sock = cli_sock;
        prun->vphttp.src_ip = ntohl(cli_addr.sin_addr.s_addr);
        prun->vphttp.src_port = ntohs(cli_addr.sin_port);

        memcpy(&prun->vphttp.cli_addr, &cli_addr, sizeof(cli_addr));
        
        cli_thread = pthread_create(&thread_id, NULL, __run_local_tcp_server, prun);
        if (cli_thread == 0)
            pthread_detach(thread_id);
    }

	if (tset_is_flg_set(&trans.vphttp.tset, TSET_PPORT_FREE))
		pplist_set_flag_port(trans.vphttp.lport);
    close_sock(&lsn_sock);
    tset_clear(&trans.vphttp.tset);
    return NULL;
}

int load_local_tcpserver(pvp_uthtrans pt, int t_state)
{
    int        tret = -1;
    pthread_t  tid;

    tret = pthread_create(&tid, NULL, __start_local_tcpserver, pt);
    if (tret != 0)
        return -1;

    if (t_state == T_WAITING)
        pthread_join(tid, NULL);
    if (t_state == T_DETACH)
        pthread_detach(tid);

    return 1;
}

