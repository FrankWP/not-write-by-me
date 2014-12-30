#include "../vpheader.h"
#include "pm_proxy.h"
#include <netinet/ip_icmp.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>

/* FIXME:
 *  ums works:
 *  1 bind ums port which equal client port
 *  2 replace client addr
 *  3 replace server addr
 *  4 replace client mac addr
 * */

static char u_mac_addr[17] = {0};
void get_mac_addr(char *mac_addr);

/* XXX: get local machine mac addr */
void get_mac_addr(char *mac_addr)
{
    int     fd;
    struct  ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);

    sprintf(mac_addr, "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x",
            (unsigned char)ifr.ifr_hwaddr.sa_data[0],
            (unsigned char)ifr.ifr_hwaddr.sa_data[1],
            (unsigned char)ifr.ifr_hwaddr.sa_data[2],
            (unsigned char)ifr.ifr_hwaddr.sa_data[3],
            (unsigned char)ifr.ifr_hwaddr.sa_data[4],
            (unsigned char)ifr.ifr_hwaddr.sa_data[5]);

    close(fd);
}

/* replace mac addr */
int rep_mac_addr(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    puts("************** before replace mac addr ****************");
    t_disbuf((unsigned char*)*ut_buf, *pack_len);
    puts("");

    /*XXX: the first bit of the mac addr was casted off */
    memcpy(*ut_buf + (*pack_len - 16), u_mac_addr + 1, 16);

    puts("************** after replace mac addr *****************");
    t_disbuf((unsigned char*)*ut_buf, *pack_len);
    puts("");

    return 1;
}

int __zsyh_init()
{
    get_mac_addr(u_mac_addr);

    return 1;
}

int __zsyh_socket(pvp_uthttp put, int sockfd)
{
    printf(" >>>>>>>>>>>>>>> bind sock put dport:%u\n", put->dport);

    if ((__gg.local_priv_addr & 0xff ) == 0){
    }
    else{
        SAI xaddr;
        memset(&xaddr, 0x00, sizeof(xaddr));

        xaddr.sin_family = AF_INET;
        xaddr.sin_addr.s_addr = htonl(__gg.outer_addr);
        xaddr.sin_port = htons(put->src_port);

        Setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR);

        char localip[32] = {0};
        inet_ultoa(__gg.outer_addr, localip);
        printf("__zsyh_socket: bind ip [%s] port [%u] \n", localip, ntohs(xaddr.sin_port));

        if (bind(sockfd, (SA *)&xaddr, sizeof(xaddr)) < 0)
        {
            char localip[32] = {0};
            inet_ultoa(__gg.outer_addr, localip);
            loginf_fmt("__zsyh_socket: bind ip [%s] port [%u] random failed\n", localip, ntohs(xaddr.sin_port));
            return -1;
        }
    }

    return 1;
}

int __zsyh_recv(pvp_uthttp put, char *ut_buf, int *pack_len, int direction)
{
    return 1;
}

int __zsyh_request(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    u32 tmsip = ntohl(__gg.inner_addr);
    u32 umsip = ntohl(__gg.outer_addr);
    u32 cliip = ntohl(put->src_ip);
    u32 serip = ntohl(put->dip);

    if (memcmp((void*)(*ut_buf + 7), (void*)&cliip, 4) == 0) {
        if (rep_mac_addr(put, ut_buf, pack_len) < 0)
            return -1;
    }

    if (memmem(*ut_buf, *pack_len, (void*)&tmsip, 4) != NULL) {
        puts(" ------------- replace tms addr!");
        t_disbuf((unsigned char*)*ut_buf, *pack_len);
        puts("");

        memreplace_pos(NULL, NULL, ut_buf, pack_len, -1, (char*)&tmsip, 4, (char*)&serip, 4);
        puts(" ------------- after replace tms addr!");
        t_disbuf((unsigned char*)*ut_buf, *pack_len);
        puts("");
    }

    if (memmem(*ut_buf, *pack_len, (void*)&cliip, 4) != NULL) {
        puts(" ------------- replace cli addr!");
        t_disbuf((unsigned char*)*ut_buf, *pack_len);
        puts("");

        memreplace_pos(NULL, NULL, ut_buf, pack_len, -1, (char*)&cliip, 4, (char*)&umsip, 4);
        puts(" ------------- after replace cli addr!");
        t_disbuf((unsigned char*)*ut_buf, *pack_len);
        puts("");
    }

    return 1;
}

int __zsyh_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    u32 tmsip = ntohl(__gg.inner_addr);
    u32 umsip = ntohl(__gg.outer_addr);
    u32 cliip = ntohl(put->src_ip);
    u32 serip = ntohl(put->dip);

    if (memmem(*ut_buf, *pack_len, (void*)&serip, 4) != NULL) {
        puts(" ------------- replace tms addr!");
        t_disbuf((unsigned char*)*ut_buf, *pack_len);
        puts("");

        memreplace_pos(NULL, NULL, ut_buf, pack_len, -1, (char*)&serip, 4, (char*)&tmsip, 4);
        puts(" ------------- after replace tms addr!");
        t_disbuf((unsigned char*)*ut_buf, *pack_len);
        puts("");
    }

    if (memmem(*ut_buf, *pack_len, (void*)&umsip, 4) != NULL) {
        puts(" ------------- replace cli addr!");
        t_disbuf((unsigned char*)*ut_buf, *pack_len);
        puts("");

        memreplace_pos(NULL, NULL, ut_buf, pack_len, -1, (char*)&umsip, 4, (char*)&cliip, 4);
        puts(" ------------- after replace cli addr!");
        t_disbuf((unsigned char*)*ut_buf, *pack_len);
        puts("");
    }


    return 1;
}

int __zsyh_close(pvp_uthttp put, int sockfd)
{
    return 1;
}

void __zsyh_quit()
{
    return;
}

