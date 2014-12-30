#include "flowcli.h"

static int __fd = -1;
static pthread_mutex_t __fd_lock = PTHREAD_MUTEX_INITIALIZER;

int write_flow_value(char *user, u32 sip, u16 sport,
        u32 dip, u16 dport, char *dvs_id, l_int flow, l_int plid)
{
    long int    seconds;
    flow_stat_t fsbuf;

    memset(&fsbuf, 0x00, sizeof(fsbuf));
    seconds = time(NULL);

    memcpy(fsbuf.usr_name, user, strlen(user));
    memcpy(fsbuf.dvs_id, dvs_id, strlen(dvs_id));
    fsbuf.sce_ip = sip;
    fsbuf.sce_port = sport;
    fsbuf.des_ip = dip;
    fsbuf.des_port = dport;
    fsbuf.fs_value = flow;
    fsbuf.t_start = seconds;
    fsbuf.platform_id = plid;

    pthread_mutex_lock(&__fd_lock);

    if (__fd < 0) {
        if ((__fd = open(FIFO_SERVER, O_WRONLY | O_NONBLOCK)) < 0) {
            pthread_mutex_unlock(&__fd_lock);
            return -1;
        }
    }
    if (write(__fd, &fsbuf, sizeof(flow_stat_t)) < 0) {
        pthread_mutex_unlock(&__fd_lock);
        close(__fd);
        return -1;
    }
    pthread_mutex_unlock(&__fd_lock);

    return 0;
}

