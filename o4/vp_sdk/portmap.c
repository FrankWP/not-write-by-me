/*
 *  @node: port map
 *  @date: 2011/8/20
 */
#include "portmap.h"

#define PM_PATH "/topconf/topvp/portmap.conf"

struct __portmap
{
    char sip[16];
    char dip[16];
    char sport[8];
    char dport[8];
    char proto[2];
    char cache[2];
} pp;

/*
 *  @ s:   string like s1:s2 format(aaa#bbb).
 *  @ s1:  store string like aaa.
 *  @ s2   store string like bbb.
 *  @ seg: Separator('#' or ':' or '\n' or other char).
 */
static char * parse_str(char *s, char *s1, char *s2, char seg)
{
    if (s == NULL || s1 == NULL || s2 == NULL)
        return NULL;

    while ((*s1++ = *s++) != '\0') {
        if (*s == seg)
            break ;
    }
    s++ ;
    while ((*s2++ = *s++) != '\0');

    return s;
}

static int start_proxy(vp_uthtrans *__ut)
{
    vp_uthtrans *ut;
    int          ret = 1;

    if (oss_malloc(&ut, sizeof(vp_uthtrans)) < 0)
        return -1;

    ut->vphttp.lport = atoi(pp.sport);
    ut->vphttp.dport = atoi(pp.dport);
    ut->vphttp.lip = inet_atoul(pp.sip);
    ut->vphttp.dip = inet_atoul(pp.dip);
    ut->vphttp.platform_id = __ut->vphttp.platform_id;
    ut->vphttp.session_tout = __ut->vphttp.session_tout;
    tset_none(&ut->vphttp.tset);

	ut->do_socket = __ut->do_socket;
    ut->do_recv = __ut->do_recv;
    ut->do_request = __ut->do_request;
    ut->do_reply = __ut->do_reply;
    ut->do_close = __ut->do_close;

    if (pp.cache[0] == 'y')
        ut->vphttp.data_cache = Y_CACHE;
    else
        ut->vphttp.data_cache = N_CACHE;

    if (pp.proto[0] == 't')
        ret = load_tcp_proxy(ut, T_DETACH);
    else if (pp.proto[0] == 'u')
        ret = load_udp_proxy(ut, T_DETACH);
    return ret;
}

/*
 *  @ format: sip:sport=dip:dport$t or $u
 *  @ t: tcp proxy, u: udp proxy.
 */
static int parse_line(char *line, vp_uthtrans *__ut)
{
    char saddr[32];
    char daddr[32];

    memset(&pp, 0x00, sizeof(pp));
    sscanf(line, "sip=%s dip=%s agent=%s cache=%s", saddr, daddr, pp.proto, pp.cache);

    if (parse_str(saddr, pp.sip, pp.sport, ':') == NULL ||
            parse_str(daddr, pp.dip, pp.dport, ':') == NULL)
        return -1;

    return start_proxy(__ut);
}

/*
 * @ proxy_type: run tcp or udp proxy.
 * @ timeout: set proxy timeout.
 */
int load_portmap_cfg(vp_uthtrans *__ut, const char *cfgPath)
{
    FILE  * fp = NULL;
    char  * line = NULL;
    size_t  len = 0;
    ssize_t read;
    int     ret = 0;

    if (__ut == NULL)
        return -1;
    if (cfgPath == NULL)
        cfgPath = PM_PATH;

    if ((fp = fopen(cfgPath, "r")) == NULL) {
        fprintf(stderr, "load portmap [%s] failed\n", cfgPath);
        return -1;
    }
    while ((read = getline(&line, &len, fp)) != -1) {
        if (!strncmp(line, "#", 1) ||
                !strncmp(line, "[portmap]", 9) ||
                !strncmp(line, "[/portmap]", 10) ||
                line == NULL)
            continue ;

        if (parse_line(line, __ut) < 0) {
            ret = -1;
            break ;
        }
    }
    if (line)
        free(line);
    return ret;
}

int load_portmap(vp_uthtrans *__ut)
{
    return load_portmap_cfg(__ut, PM_PATH);
}
