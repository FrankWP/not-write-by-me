/*****************************************************************
 * Destription: flowsvr.c
 * use the hash method, also use the thread pool, the efficiency
 * of two method have not test, it should be almost.
 * auth: ysun
 ******************************************************************/
#include "../vpheader.h"
#include "../vp_sdk/defflow.h"

#define  vs_tout     5      // time out
#define  vs_tnum     120    // video stream way
#define  vs_tcfv     5    // count flowvalue time
#define  vs_tkey     100    // 1~99
#define  fs_okey     0x03   // the hash key 

#define  PID_FLOWSVR "flowsvr.pid"

#define ASSERT(p) \
    if (!p) return -1;

typedef struct flow_operate
{
    MYSQL *mysql_conn;
    flow_stat_t *pstat[vs_tnum];
}floperate, *pflow;

static floperate *g_pflow = NULL;

/*
 *  create hash key, get the camera id to fetch 
 *  the last three byte 
 */
int get_flow_key(char *pdvs)
{
    int  i, hkey;
    char key[fs_okey + 1];

    memset(key, 0x00, sizeof(key));
    pdvs = pdvs + (strlen(pdvs) - fs_okey);

    for (i = 0; i < fs_okey; i++) {
        key[i] = *pdvs++;
    }

    hkey = (atoi(key)/vs_tkey + atoi(key) % vs_tkey);
    return hkey;
}

int insert_into_database(flow_stat_t *pvalue)
{
    ASSERT(pvalue);

    char buf[1024];
    char pid[16];
    char sql_format[512];

    memset(sql_format, 0x00, sizeof(sql_format));
    memset(buf, 0x00, sizeof(buf));

    strcpy(sql_format, "insert into vgap_flow (flow_user_name, flow_source_ip, flow_source_port, flow_des_ip, ");
    strcat(sql_format, "flow_des_port, flow_devis_id, \
            flow_start_time, flow_end_time, flow_value, flow_platform_id) values ('%s', ");
    strcat(sql_format, "%u, %d, %u, %d, '%s', %d, %d, %d, '%s')");

    sprintf(pid, "%d", pvalue->platform_id);
    sprintf(buf, sql_format, pvalue->usr_name, pvalue->sce_ip, pvalue->sce_port,
            pvalue->des_ip, pvalue->des_port, pvalue->dvs_id, pvalue->t_start, pvalue->t_end,
            pvalue->fs_value, pid);

    if (mysql_query(g_pflow->mysql_conn, buf)) {
        syslog(LOG_INFO, "insert into database error %s\n", mysql_error(g_pflow->mysql_conn));
        //mysql_close(g_pflow->mysql_conn);
        return -1;
    }
    return 0;
}

flow_stat_t * search_flow_data(char *dvs_id)
{
    int  key;
    flow_stat_t *pfstat;

    key = get_flow_key(dvs_id);

    for (pfstat = g_pflow->pstat[key]; pfstat; pfstat = pfstat->plink) {
        if (!strncmp(dvs_id, pfstat->dvs_id, strlen(dvs_id)))
            return pfstat;
    }
    return NULL;
}

int delete_aflow_data()
{
    ASSERT(g_pflow);
    int i;
    //flow_stat_t *pfs = NULL;
    flow_stat_t *ph = NULL;

    for (i = 0; i < vs_tnum; i++) {
        ph = g_pflow->pstat[i];
        while (ph) {
            //pfs = ph;
            ph = ph->plink;
            oss_free((void *)&ph);
        }
    }
    return 0;
}

int delete_flow_data(char *dvs_id)
{
    ASSERT(g_pflow);

    int  key;
    flow_stat_t *pfs, *prev;

    key = get_flow_key(dvs_id);
    pfs = g_pflow->pstat[key];

    if (pfs == NULL)
        return -1;
    else {
        prev = pfs;
        while (pfs && strncmp(pfs->dvs_id, dvs_id, strlen(dvs_id))) {
            prev = pfs;
            pfs = pfs->plink;
        }
        if(prev != pfs) {
            prev->plink = pfs->plink;
            oss_free((void *)&pfs);
        } else {
            if (pfs->plink)
                g_pflow->pstat[key] = pfs->plink;
            else
                g_pflow->pstat[key] = NULL;
            oss_free((void *)&pfs);
        }
    }
    return 0;
}

int del_tout_flow_data()
{
    ASSERT(g_pflow);

    int  i;
    u32  s;
    flow_stat_t *pfs;

    s = time(NULL);
    for (i = 0; i < vs_tnum; i++) {
        pfs = g_pflow->pstat[i];
        while (pfs) {
            if (s - pfs->t_update >= vs_tout) 
                delete_flow_data(pfs->dvs_id);
            pfs = pfs->plink;
        }
    }
    return 0;
}

int insert_flow_data(flow_stat_t *pbuf)
{
    ASSERT(g_pflow);

    int         key;
    u32         lseconds;
    flow_stat_t *pvalue;

    key = get_flow_key(pbuf->dvs_id);
    pvalue = search_flow_data(pbuf->dvs_id);

    if (pvalue == NULL) {
        pvalue = (flow_stat_t *)malloc(sizeof(flow_stat_t));
        memset(pvalue, 0x00, sizeof(flow_stat_t));
        pvalue->plink = g_pflow->pstat[key];
        g_pflow->pstat[key] = pvalue;
        memcpy(pvalue, pbuf, sizeof(flow_stat_t));
        pvalue->t_start = time(NULL);
        pvalue->t_update = time(NULL);
        printf("insert_flow_data: new cam [%s]\n", pbuf->dvs_id);
        //usleep(1000*4);
        return 0;
    }
    if (pbuf->fs_value > 0) {
        lseconds = time(NULL);
        puts("insert_flow_data: xxx !");
        //usleep(1000*4);
        if ((lseconds - pvalue->t_start) >= vs_tcfv) {
            puts("insert_flow_data: insert database! --------------------------------");
            //usleep(1000*4);
            pvalue->t_end = lseconds;
            insert_into_database(pvalue);
            pvalue->t_start = time(NULL);
            pvalue->t_update = time(NULL);
            pvalue->fs_value = 0;
        } else {
            pvalue->fs_value = pbuf->fs_value + pvalue->fs_value;
            pvalue->t_update = time(NULL);
        }
    }
    return 0;
}

int read_flow_data()
{
    int         fd;
    fd_set      rfds;
    flow_stat_t fsbuf;

	unlink(FIFO_SERVER);
    if ((mkfifo(FIFO_SERVER, FIFOMODE) < 0) && (errno != EEXIST)) {
        syslog(LOG_INFO, "cannot create fifoserver");
        return -1;
    }
    if ((fd = open(FIFO_SERVER, OPENMODE)) < 0)
	{
		syslog(LOG_INFO, "open FIFO:%s failed.", FIFO_SERVER);
        return -1;
	}

    int fdret = 0;
    for(;;) {
        del_tout_flow_data();
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        puts("read_flow_data: read waiting.");
        fdret = select(fd + 1, &rfds, NULL, NULL, NULL);
        if (fdret <= 0)
        {
            puts("read_flow_data: read failed!");
            continue ;
        }
        puts("read_flow_data: read ok!");
        if (fdret > 0) {
            if (FD_ISSET(fd, &rfds)) {
                memset(&fsbuf, 0x00, sizeof(fsbuf));
                if (read(fd, &fsbuf, sizeof(fsbuf)) < 0)
                    return -1;
                printf("read_flow_data:%ld\n", fsbuf.fs_value);

                if (fsbuf.fs_value > 0) {
                    insert_flow_data(&fsbuf);
                    continue ;
                }
                sleep(1);
            }
        }
    }
    return 0;
}

static void quit_system(int n)
{
    delete_aflow_data();
    oss_free((void *)&g_pflow);
    remove_pid_file(PID_FLOWSVR);
	modmysql_close();
    exit(n);
}

int main(int argc, char *argv[])
{
    int   i;
	bool  debug_mod = false;

	if ( (argc == 2) && (strcmp(argv[1], "-d") == 0))
		debug_mod = true;

    openlog("flowsvr", LOG_CONS | LOG_PID | LOG_PERROR, LOG_USER);

	if ((debug_mod == false) && (create_daemon() != 0))
        return 0;

    if (create_pid_file(PID_FLOWSVR) <= 0)
	{
		logdbg_out("cretae pid file failed!");
        return 0;
	}

    signal(SIGINT, quit_system);
    signal(SIGTERM, quit_system);

	if (modmysql_open(DB_NAME, 1) == false)
	{
		logwar_out("[flowvalue] init mysql module failed!");		
		goto end_flowsvr;
	}

    g_pflow = (floperate *)malloc(sizeof(floperate));
    for (i = 0; i < vs_tnum; i++)
        g_pflow->pstat[i] = NULL;

	if ((g_pflow->mysql_conn = modmysql_get_freeconn()) == NULL)
	{
		logwar_out("[flowvalue] get mysql connection failed!");		
		goto end_flowsvr;
	}

    read_flow_data();

end_flowsvr:
    closelog();
    quit_system(0);

    return 0;
}

