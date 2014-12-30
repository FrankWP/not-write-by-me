#include "pool_port.h"

static  pp_list   * g_pplist = NULL;
pthread_mutex_t     pp_mutex;
pthread_mutexattr_t pp_attr;

struct play_record playrecord;

void pplist_init_value()
{
    int i;
    int port;

    port = INIT_PORT;

    for (i = 0; i < PP_TOTAL; i++) {
        (g_pplist + i)->flag = N_USE;
        (g_pplist + i)->port = port;
        (g_pplist + i)->dport = 0;
        (g_pplist + i)->dip = 0;
        ++port;
    }
}

void pplist_set_flag(pp_list *pplist, u16 port)
{
    int i;

    pthread_mutex_lock(&pp_mutex);

    for (i = 0; i < PP_TOTAL; i++) {
        if ((pplist + i)->port == port) {
            (pplist + i)->flag = N_USE;
            (pplist + i)->dip = 0;
            pthread_mutex_unlock(&pp_mutex);
            return ;
        }
    }

    pthread_mutex_unlock(&pp_mutex);
}

void pplist_set_flag_port(u16 port)
{
    int i;

    pthread_mutex_lock(&pp_mutex);

    for (i = 0; i < PP_TOTAL; i++) {
        if ((g_pplist + i)->port == port) {
            (g_pplist + i)->flag = N_USE;
            (g_pplist + i)->dip = 0;
            pthread_mutex_unlock(&pp_mutex);
            return ;
        }
    }

    pthread_mutex_unlock(&pp_mutex);
}

static int g_lport = INIT_PORT;

u16 pplist_getidle_port_x()
{
    int count = 0;
    u16 findport;

    pthread_mutex_lock(&pp_mutex);

    while (1) {
        if (g_lport == INIT_PORT + PP_TOTAL) 
        {
            g_lport = INIT_PORT;
            if (count++ > 0) 
            {
                /*
                 * not idle port in the portpool
                 * find circle
                 */
                pthread_mutex_unlock(&pp_mutex);
                return 0;
            }
        }
        if ((g_pplist + (g_lport - INIT_PORT))->flag == N_USE) 
        {
            (g_pplist + (g_lport - INIT_PORT))->flag = Y_USE;
            break ;
        }
        ++g_lport;
    }
    findport = g_lport;
    ++g_lport;
    pthread_mutex_unlock(&pp_mutex);
    return findport;
}

u16 pplist_getidle_port()
{
    int i;

    pthread_mutex_lock(&pp_mutex);

    for (i = 0; i < PP_TOTAL; i++) {
        if ((g_pplist + i)->flag == N_USE) {
            (g_pplist + i)->flag = Y_USE;
            pthread_mutex_unlock(&pp_mutex);
            return (g_pplist + i)->port;
        }
    }

    pthread_mutex_unlock(&pp_mutex);

    return 0;
}

int pplist_getidle_port2_step(u16 *host_port1, u16 *host_port2, int step)
{
    int i;
	//int n = 0;
    if (step < 1)
        return 0;
    if (step > PP_TOTAL)
        return 0;

    pthread_mutex_lock(&pp_mutex);

    for (i = 0; i < PP_TOTAL; i += step) {
        if ((g_pplist + i)->flag == N_USE) {
            (g_pplist + i)->flag = Y_USE;
            (g_pplist + i + step)->flag = Y_USE;
			*host_port1 = (g_pplist + i)->port;
			*host_port2 = (g_pplist + i + step)->port;
            pthread_mutex_unlock(&pp_mutex);
			return 2;
            //return (g_pplist + i)->port;
        }
    }

    pthread_mutex_unlock(&pp_mutex);

    return 0;
}

int pplist_getidle_port2(u16 *port1, u16 *port2)
{
    /*
    int i;
	//int n = 0;

    pthread_mutex_lock(&pp_mutex);

    for (i = 0; i < PP_TOTAL; i++) {
        if ((g_pplist + i)->flag == N_USE) {
            (g_pplist + i)->flag = Y_USE;
            (g_pplist + i + 1)->flag = Y_USE;
			*port1 = (g_pplist + i)->port;
			*port2 = (g_pplist + i + 1)->port;
            pthread_mutex_unlock(&pp_mutex);
			return 2;
            //return (g_pplist + i)->port;
        }
    }

    pthread_mutex_unlock(&pp_mutex);
    */
    
   // return 0;
   return pplist_getidle_port2_step(port1, port2, 1);
}

u16  pplist_find_port(u32 dip)
{
    int i;

    pthread_mutex_lock(&pp_mutex);
    for (i = 0; i < PP_TOTAL; i++) {
        if ((g_pplist + i)->dip == dip) {
            pthread_mutex_unlock(&pp_mutex);
            return (g_pplist + i)->port;
        }
    }
    pthread_mutex_unlock(&pp_mutex);

    return 0;
}

u16 pplist_getidle_port_ip(u32 dip)
{
    int i;

    pthread_mutex_lock(&pp_mutex);
    for (i = 0; i < PP_TOTAL; i++) {
        if ((g_pplist + i)->flag == N_USE) {
            (g_pplist + i)->flag = Y_USE;
            (g_pplist + i)->dip = dip;
            pthread_mutex_unlock(&pp_mutex);
            return (g_pplist + i)->port;
        }
    }
    pthread_mutex_unlock(&pp_mutex);

    return 0;
}

/*
 * @ get two continue port, use for keeplive.
 */
u16 pplist_getidle_port_t(int offset)
{
    int i;

    pthread_mutex_lock(&pp_mutex);

    for (i = 0; i < PP_TOTAL; i++) {
        if ((g_pplist + i)->flag == N_USE
                && (g_pplist + i + offset)->flag == N_USE)
        {
            (g_pplist + i)->flag = Y_USE;
            (g_pplist + i + offset)->flag = Y_USE;
            pthread_mutex_unlock(&pp_mutex);
            return (g_pplist + i)->port;
        }
    }

    pthread_mutex_unlock(&pp_mutex);

    return 0;
}

void pplist_print()
{
    int i;

    for (i = 0; i < PP_TOTAL; i++) {
        printf("port = %d flag = %d\n",
                (g_pplist + i)->port, (g_pplist + i)->flag);
    }
}

pp_list * create_pp_smem(const char * psmid)
{
    int       fd, oflags;
    pp_list  *pplist;

    oflags = O_RDWR | O_CREAT | O_EXCL;
    fd = shm_open(psmid, oflags, FILE_MODE);
    if (fd == -1) {
        if (errno == EEXIST)
            fd = shm_open(psmid, O_RDWR, FILE_MODE);
        else
            return NULL;
    }
    pplist = (pp_list*)mmap(NULL, sizeof(pp_list) * PP_TOTAL,
                  PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    ftruncate(fd, sizeof(pp_list) * PP_TOTAL);
    close(fd);

    return pplist;
}

int load_portpool()
{
    INIT_PP_MUTEX();

    g_pplist = create_pp_smem(PP_SMNAME);
    if (g_pplist == NULL) {
        syslog(LOG_INFO, "create port pool sharemem faliled.");
        return -1;
    }
    pplist_init_value();

    return 1;
}

void destroy_portpool()
{
    DESTROY_PP_MUTEX();
}

static pthread_mutex_t g_rmutex = PTHREAD_MUTEX_INITIALIZER;

void init_record_server()
{
    int i;

    playrecord.start_port = PORT_RECORD;

    for (i = 0; i < IP_COUNT; i++) {
        playrecord.lport[i] = playrecord.start_port++;
        playrecord.dport[i] = 0;
        playrecord.flag[i] = N_USE;
        memset(playrecord.dip[i], 0x00, sizeof(playrecord.dip[i]));
    }
}

u16 search_record_server(char *dip)
{
    int i = 0;
    int lport = 0;

    if (dip == NULL)
        return 0;

    pthread_mutex_lock(&g_rmutex);

    for (i = 0; i < IP_COUNT; i++)
    {
        if (playrecord.flag[i] == Y_USE &&
                !strcmp(dip, playrecord.dip[i]))
        {
            lport = playrecord.lport[i];
            break;
        }
    }

    pthread_mutex_unlock(&g_rmutex);

    return lport;
}

u16 set_record_server(char *dip)
{
    int i = 0;
    u16 lport = 0;

    if (dip == NULL)
        return 0;

    pthread_mutex_lock(&g_rmutex);

    for (i = 0; i < IP_COUNT; i++)
    {
        if (playrecord.flag[i] == N_USE)
        {
            playrecord.flag[i] = Y_USE;
            strcpy(playrecord.dip[i], dip);
            lport = playrecord.lport[i];
            break;
        }
    }

    pthread_mutex_unlock(&g_rmutex);

    return lport;
}

u16 x_search_server(char *dip, u16 dport)
{
    int i = 0;
    u16 lport = 0;

    if (dip == NULL)
        return 0;

    pthread_mutex_lock(&g_rmutex);

    for (i = 0; i < IP_COUNT; i++) {
        if (playrecord.flag[i] == Y_USE &&
                !strcmp(dip, playrecord.dip[i]) &&
                dport == playrecord.dport[i])
        {
            lport = playrecord.lport[i];
            break;
        }
    }

    pthread_mutex_unlock(&g_rmutex);

    return lport ;
}

u16  x_search_dst_server(u16 lport, char *dip, u16 *dport)
{
    int i = 0;
    u16 dst_port = 0;

    if (dip == NULL || lport == 0)
        return 0;

    pthread_mutex_lock(&g_rmutex);

    for (i = 0; i < IP_COUNT; i++) {
        if (playrecord.flag[i] == Y_USE &&
                lport == playrecord.lport[i])
        {
            strcpy(dip, playrecord.dip[i]);
            dst_port = playrecord.dport[i];
            if (dport != NULL)
                *dport = dst_port;
            break;
        }
    }

    pthread_mutex_unlock(&g_rmutex);

    return dst_port;
}

u16 x_set_server(char *dip, u16 dport)
{
    int i = 0;
    u16 lport = 0;

    if (dip == NULL)
        return 0;

    pthread_mutex_lock(&g_rmutex);

    for (i = 0; i < IP_COUNT; i++)
    {
        if (playrecord.flag[i] == N_USE)
        {
            playrecord.flag[i] = Y_USE;
            playrecord.dport[i] = dport;
            strcpy(playrecord.dip[i], dip);
            lport = playrecord.lport[i];
            break ;
        }
    }

    pthread_mutex_unlock(&g_rmutex);

    return lport;
}

u16 x_get_idle_port()
{
    int i;

    pthread_mutex_lock(&g_rmutex);

    for (i = 0; i < IP_COUNT; i++)
    {
        if (playrecord.flag[i] == N_USE)
        {
            playrecord.flag[i] = Y_USE;
            pthread_mutex_unlock(&g_rmutex);
            return playrecord.lport[i];
        }
    }

    pthread_mutex_unlock(&g_rmutex);

    return 0;
}

u16 x_set_idle_port(u16 dport)
{
    int i;

    pthread_mutex_lock(&g_rmutex);

    for (i = 0; i < IP_COUNT; i++)
    {
        if (playrecord.flag[i] == Y_USE &&
                dport == playrecord.dport[i])
        {
            playrecord.flag[i] = N_USE;
            playrecord.dport[i] = 0;
            memset(playrecord.dip[i], 0x00, sizeof(playrecord.dip[i]));
            pthread_mutex_unlock(&g_rmutex);
            return 1;
        }
    }

    pthread_mutex_unlock(&g_rmutex);

    return 0;
}

u16 x_set_idle_ipport(char *dip, u16 dport)
{
    int i;

    pthread_mutex_lock(&g_rmutex);

    for (i = 0; i < IP_COUNT; i++)
    {
        if (playrecord.flag[i] == Y_USE &&
                dport == playrecord.dport[i] &&
                !strcmp(dip, playrecord.dip[i]))
        {
            playrecord.flag[i] = N_USE;
            playrecord.dport[i] = 0;
            memset(playrecord.dip[i], 0x00, sizeof(playrecord.dip[i]));
            pthread_mutex_unlock(&g_rmutex);
            return 1;
        }
    }
    pthread_mutex_unlock(&g_rmutex);
    return 0;
}

struct _pool_port_segment
{
	u16 base_port;
	int step;
	int count;
	char *flag;
};

struct _pool_port_segment g_pp_segment = {0,0,0, NULL};
pthread_mutex_t     pp_seg_mutex;

int init_segment_port(u16 base, int step, int count)
{
    pthread_mutex_init(&pp_seg_mutex, NULL);
	g_pp_segment.base_port = base;
	g_pp_segment.step = step;
	g_pp_segment.count = count;
	oss_malloc(&(g_pp_segment.flag), count * sizeof(char));
	//g_pp_segment.flag = (char*)malloc(count * sizeof(char));
	//memset(g_pp_segment.flag, 0, count * sizeof(char));
	return 1;
}

u16 get_idle_segment_port()
{
	u16 res = 0;
	int n = 0;

pthread_mutex_lock(&pp_seg_mutex);
	while (n < g_pp_segment.count)
	{
		if (g_pp_segment.flag[n] == N_USE)
		{
			g_pp_segment.flag[n] = Y_USE;
			break;
		}
		++n;
	}
pthread_mutex_unlock(&pp_seg_mutex);
	if (n < g_pp_segment.count)
		res = g_pp_segment.base_port + n * g_pp_segment.step;
	return res;
}

void free_idle_segment_port(u16 port)
{
	int nPos = 0;
	if (((port - g_pp_segment.base_port) % g_pp_segment.step) != 0)
	{
		logdbg_out("Pool port: Invalid segment port");
		return;
	}
	nPos = (port - g_pp_segment.base_port) / g_pp_segment.step;
pthread_mutex_lock(&pp_seg_mutex);
	g_pp_segment.flag[nPos] = N_USE;
pthread_mutex_unlock(&pp_seg_mutex);
}

void destroy_segment_port()
{
    pthread_mutex_destroy(&pp_seg_mutex);
	oss_free(&(g_pp_segment.flag));
}

