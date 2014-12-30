#include "vp_distribute.h"

void vsnode_print(v_ser *pser);
void vsnode_del_all(vs_list *pvslist, v_ser *pser);

char * vser_get_dtid(char * dtid)
{
    sprintf(dtid, "%d", get_sharemem_pid());
    return dtid;
}

int dt_empty(vs_list * pvslist)
{
    if (pvslist == NULL) {
        syslog(LOG_ERR, "vslist is empty");
        return 1;
    }
    return 0;
}

/*
 *  x_mark: x_sign or dt_id.
 */
int vser_find(v_ser *pser,
                 u32 dip,
                 u16 dport,
                 char *x_mark)
{
    int ret = 0;

    if (x_mark != NULL) {
        if (!strcmp(pser->vway.x_sign, x_mark)
                || !strcmp(pser->vway.dt_id, x_mark))
            ret = 1;
    } else {
        if (pser->vway.dip == dip && pser->vway.dport == dport)
            ret = 1;
    }
    return ret;
}

v_ser * vser_search(vs_list *pvslist,
                    u32 dip,
                    u16 dport,
                    char *x_mark)
{
    lh    *pos;
    v_ser *pser = NULL;

    list_for_each(pos, &pvslist->vser.list) {
        pser = list_entry(pos, v_ser, list);
        if (vser_find(pser, dip, dport, x_mark))
            return pser;
    }
    return pser;
}

void vser_del_all(vs_list *pvslist)
{
    lh    *pos;
    v_ser *pser;

    list_for_each(pos, &pvslist->vser.list) {
        pser = list_entry(pos, v_ser, list);
        vsnode_del_all(pvslist, pser);
        __vslist_del(pvslist, pser, pos);
    }
}

void vser_del(vs_list *pvslist,
              u32 dip,
              u16 dport,
              char *x_mark)
{
    lh    *pos;
    v_ser *pser;

    list_for_each(pos, &pvslist->vser.list) {
        pser = list_entry(pos, v_ser, list);
        if (vser_find(pser, dip, dport, x_mark)) {
            vsnode_del_all(pvslist, pser);
            __vslist_del(pvslist, pser, pos);
            return ;
        }
    }
}

v_ser * vser_add(vs_list *pvslist,
                    u32 dip,
                    u16 dport,
                    char *x_mark)
{
    v_ser *pser;

    if (oss_malloc(&pser, sizeof(v_ser)) < 0)
        return NULL;

    init_vser_node(pser);

    if (x_mark != NULL)
        strcpy(pser->vway.x_sign, x_mark);
    else {
        pser->vway.dip = dip;
        pser->vway.dport = dport;
    }
    vser_get_dtid(pser->vway.dt_id);

    __vser_add_tail(pvslist, pser);

    return pser;
}

void lser_set(v_ser *pser, u32 lip, u16 lport)
{
    pser->vway.lip = lip;
    pser->vway.lport = lport;
}

void vser_print(vs_list *pvslist)
{
    lh     *pos;
    v_ser  *pser;

    list_for_each(pos, &pvslist->vser.list) {
        pser = list_entry(pos, v_ser, list);
        printf("v_num = %d lip = %d lport = %d dip = %d dport = %d\n\n",
                pser->vway.v_num,
                pser->vway.lip, pser->vway.lport,
                pser->vway.dip, pser->vway.dport);
        printf("----------------------------------------\n");
        vsnode_print(pser);
        printf("----------------------------------------\n");
    }
}

vv_node * vsnode_add(vs_list *pvslist,
                     int sockfd,
                     SAI cli_addr,
                     int x_mark,
                     v_ser *pser)
{
    vv_node *pn;

    if (oss_malloc(&pn, sizeof(vv_node)) < 0)
        return NULL;

    pn->x_mark = x_mark;
    pn->cli_sock = sockfd;
    memcpy(&pn->cli_addr, &cli_addr, sizeof(cli_addr));;
    vser_addnum(pvslist, pser);

    __vsnode_add_tail(pvslist, pser, pn);

    return pn;
}

int vsnode_del(vs_list * pvslist,
               SAI cli_addr,
               int sockfd,
               v_ser *pser)
{
    lh       *pos, *qn;
    vv_node  *pn, *pnn;

    list_for_each_safe(pos, qn, &pser->vvlist.list) {
        pn = list_entry(pos, vv_node, list);
        if (pn->cli_sock == sockfd ||
                !memcmp(&pn->cli_addr, &cli_addr, sizeof(cli_addr)))
        {
            if (pser->vway.v_num > 1) {
                pnn = list_entry(pos->prev, vv_node, list);
                if (pn->x_mark == NODE_LEADER)
                    pnn->x_mark = NODE_LEADER;
                return DT_NOSEND;
            } else {
                vser_del(pvslist,
                         pser->vway.dip,
                         pser->vway.dport,
                         pser->vway.x_sign);
                return DT_QUIT;
            }
        }
    }
    return DT_SEND;
}

void vsnode_del_all(vs_list *pvslist, v_ser *pser)
{
    lh      *pos, *qn;
    vv_node *pn;

    list_for_each_safe(pos, qn, &pser->vvlist.list) {
        pn = list_entry(pos, vv_node, list);
        __vslist_del(pvslist, pn, pos);
    }
}

void vsnode_print(v_ser *pser)
{
    lh       *pos;
    vv_node  *pn;

    list_for_each(pos, &pser->vvlist.list) {
        pn = list_entry(pos, vv_node, list);
        printf("cliaddr = %s:%d\n",
                inet_ntoa(pn->cli_addr.sin_addr),
                ntohs(pn->cli_addr.sin_port));
    }
}

void dt_quit(vs_list *pvslist)
{
    vser_del_all(pvslist);
}

void dt_print(vs_list *pvslist)
{
    vser_print(pvslist);
}

int dt_recv_x(vs_list *pvslist,
              int sockfd,
              SAI cli_addr,
              char *data_buf,
              int ret,
              v_ser *pser)
{
    int    x_mark;
    int    x_cmd;

    if (ret <= 0)
        return vsnode_del(pvslist, cli_addr, sockfd, pser);

    x_cmd = parse_reqst_cmd(sockfd, cli_addr, data_buf);
    if (x_cmd == DT_CLOSE_CONNECT)
        return vsnode_del(pvslist, cli_addr, sockfd, pser);

    if (!pser->vway.v_num)
        x_mark = NODE_LEADER;
    else
        x_mark = NODE_BEHIND;

    if (vsnode_add(pvslist, sockfd, cli_addr, x_mark, pser) == NULL)
        return DT_ERROR;

    if (x_mark == NODE_BEHIND)
        return DT_NOSEND;

    return DT_SEND;
}

void dt_send_x(vs_list *pvslist,
               char *data_buf,
               clivlist *pcvn,
               int rx,
               int sockfd,
               v_ser *pser)
{
    int       x_ret;
    lh       *pos;
    vv_node  *pn;

    list_for_each(pos, &pser->vvlist.list) {
        pn = list_entry(pos, vv_node, list);

        x_ret = sendto(sockfd, data_buf, rx, 0,
                      (SA *)&pn->cli_addr, sizeof(pn->cli_addr));
        if (x_ret > 0)
            write_flow_value(pcvn->visit_user, ntohl(pn->cli_addr.sin_addr.s_addr),
                             ntohs(pn->cli_addr.sin_port), pcvn->dip,
                             pcvn->dvport, pcvn->camera_id,
                             rx, pcvn->platform_id);
        else
            vsnode_del(pvslist, pn->cli_addr, sockfd, pser);
    }
}

vs_list * __create_vs_smem(const char * smid)
{
    int       fd;
    int       flag;
    vs_list * pvslist;

    flag = O_RDWR | O_CREAT | O_EXCL;

    fd = shm_open(smid, flag, FILE_MODE);
    if (fd == -1) {
        if (errno == EEXIST)
            fd = shm_open(smid, O_RDWR, FILE_MODE);
        else
            return NULL;
    }
    pvslist = (vs_list *)mmap(NULL, sizeof(vs_list),
                              PROT_READ | PROT_WRITE,
                              MAP_SHARED, fd, 0);
    ftruncate(fd, sizeof(vs_list));
    close(fd);

    return pvslist;
}

vs_list * create_dt_smem(const char * smid)
{
    return __create_vs_smem(smid);
}

vs_list * get_dt_smem(const char * smid)
{
    return __create_vs_smem(smid);
}
