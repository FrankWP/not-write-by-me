#include "../vpheader.h"

#define  SAVE_SCES  "success"
#define  SAVE_FAID  "failed"

#define  SYS_PATH   "/topapp/topvp/"
#define  TMP_PATH   "/topapp/topvp/.tmp.txt"
#define  NET_PATH   "/etc/sysconfig/network-scripts/ifcfg-"
#define  SER_CONF   "/topconf/topvp/platforms"

#define REQ_BASENUM 10
#define SZ_SRVID    32
#define rtotal sizeof(tms_reqst)/sizeof(tms_reqst[0])

const static char SYS_MANA_VER[] = "1.2";
const static char PROG_NAME[] = "sys-manager";
const static int  max_err_times = 5;

int read_info(int sock)
{
    FILE    *fp;
    char    cmd[64] = {0};
    char    buf[2048] = {0};

    if ((fp = fopen(TMP_PATH, "r")) == NULL)
        return -1;

    memset(buf, 0x00, sizeof(buf));
    if (__fread(buf, sizeof(buf), 1, fp) < 0)
        return -1;
    fclose(fp);

    sprintf(cmd, "rm -rf %s >/dev/null 2>&1", TMP_PATH);
    system(cmd);
    return Send(sock, buf, strlen(buf), 0);
}

int get_sysinfo(int sock, char recvmsg[])
{
    char    cmd[64] = {0};

    memset(cmd, 0, sizeof(cmd));
    int i = (unsigned char)recvmsg[0];
    switch (i) {
        case 10 + REQ_BASENUM:
            sprintf(cmd, "sh %ssysif.sh sd >%s", SYS_PATH, TMP_PATH);     // system describe
            loginf_out("系统管理者查询系统描述信息.");
            break ;
        case 11 + REQ_BASENUM:
            sprintf(cmd, "sh %ssysif.sh sn >%s", SYS_PATH, TMP_PATH);     // system name
            loginf_out("系统管理者查询系统主机名.");
            break ;
        case 12 + REQ_BASENUM:
            sprintf(cmd, "sh %ssysif.sh srt >%s", SYS_PATH, TMP_PATH);    // system runtime
            loginf_out("系统管理者查询系统运行时间.");
            break ;
        case 18 + REQ_BASENUM:
            sprintf(cmd, "sh %ssysif.sh as >%s", SYS_PATH, TMP_PATH);     // system service
            loginf_out("系统管理者查询系统运行服务.");
            break ;
        case 23 + REQ_BASENUM:
            sprintf(cmd, "sh %ssysif.sh cl >%s", SYS_PATH, TMP_PATH);     // cpu percent of idle
            loginf_out("系统管理者查询系统内存使用率.");
            break ;
        default:
            break ;
    }
    system(cmd);
    return read_info(sock);
}

int get_meminfo(int sock, char recvmsg[])
{
    char    cmd[64] = {0};

    memset(cmd, 0x00, sizeof(cmd));
    switch ((unsigned char)recvmsg[0]) {
        case 13 + REQ_BASENUM:
            sprintf(cmd, "sh %ssysif.sh mt >%s", SYS_PATH, TMP_PATH);     // memory total
            loginf_out("系统管理者查询系统全部内存.");
            break ;
        case 14 + REQ_BASENUM:
            sprintf(cmd, "sh %ssysif.sh ml >%s", SYS_PATH, TMP_PATH);     // memory no use
            loginf_out("系统管理者查询系统剩余内存.");
            break ;
        case 24 + REQ_BASENUM:
            sprintf(cmd, "sh %ssysif.sh me >%s", SYS_PATH, TMP_PATH);    // memory alarm
            loginf_out("系统管理者查询系统内存告警.");
            break ;
        default:
            break ;
    }
    system(cmd);
    return read_info(sock);
}

int get_netinfo(int sock, char recvmsg[])
{
    char    cmd[64] = {0};

    memset(cmd, 0x00, sizeof(cmd));
    switch ((unsigned char)recvmsg[0]) {
        case 19 + REQ_BASENUM:
            sprintf(cmd, "sh %ssysif.sh ns >%s", SYS_PATH, TMP_PATH);     // network status
            loginf_out("系统管理者查询系统网络状态.");
            break ;
        case 20 + REQ_BASENUM:
            sprintf(cmd, "sh %ssysif.sh at >%s", SYS_PATH, TMP_PATH);     // arp list
            loginf_out("系统管理者查询系统ARP列表.");
            break ;
        case 21 + REQ_BASENUM:
            sprintf(cmd, "sh %ssysif.sh tst >%s", SYS_PATH, TMP_PATH);    // tcp session list
            loginf_out("系统管理者查询系统访问列表.");
            break ;
        case 22 + REQ_BASENUM:
            sprintf(cmd, "sh %ssysif.sh ntf >%s", SYS_PATH, TMP_PATH);    // network flow
            loginf_out("系统管理者查询系统网络流量.");
            break ;
        default:
            break ;
    }
    system(cmd);
    return read_info(sock);
}

int get_diskinfo(int sock, char recvmsg[])
{
    char    cmd[64] = {0};

    memset(cmd, 0x00, sizeof(cmd));
    switch (recvmsg[0]) {
        case 15 + REQ_BASENUM:
            sprintf(cmd, "sh %ssysif.sh dt >%s", SYS_PATH, TMP_PATH);     // harddisk total
            loginf_out("系统管理者查询系统硬盘总容量.");
            break ;
        case 16 + REQ_BASENUM:
            sprintf(cmd, "sh %ssysif.sh dl >%s", SYS_PATH, TMP_PATH);     // harddisk no use
            loginf_out("系统管理者查询系统剩余硬盘容量.");
            break ;
        case 17 + REQ_BASENUM:
            sprintf(cmd, "sh %ssysif.sh pdu >%s", SYS_PATH, TMP_PATH);    // harddisk percent of idle
            loginf_out("系统管理者查询系统剩余硬盘空间百分比.");
            break ;
        default:
            break ;
    }
    system(cmd);
    return read_info(sock);
}

static int read_net_config(char file_buf[], char * net_dev)
{
    int     fd;
    char    *ptok;
    size_t  len = 0;
    char    buf[64] = {0};
    char    net_config[256] = {0};
    char    file_path[64] = {0};

    memset(net_config, 0x00, sizeof(net_config));
    memset(file_path, 0x00, sizeof(file_path));
    sprintf(file_path, "%s%s", NET_PATH, net_dev);

    if ((fd = open(file_path, O_RDONLY)) == -1) {
        loginf_out("系统管理者读取网络配置打开配置文件错误.");
        return -1;
    }
    if ((len = read(fd, net_config, sizeof(net_config))) <= 0) {
        loginf_out("系统管理者读取网络配置错误");
        return -1;
    }

    ptok = strtok(net_config, "\n");
    while (ptok != NULL) {
        memset(buf, 0x00, sizeof(buf));

        if (!strncmp(ptok, "IPADDR=", strlen("IPADDR="))) {
            sprintf(buf, "ip=%s\n", ptok + strlen("IPADDR="));
            strcat(file_buf, buf);
        } else if (!strncmp(ptok, "NETMASK=", strlen("NETMASK"))) {
            sprintf(buf, "mask=%s\n", ptok + strlen("NETMASK="));
            strcat(file_buf, buf);
        } else if (!strncmp(ptok, "GATEWAY=", strlen("GATEWAY="))) {
            sprintf(buf, "gateway=%s\n", ptok + strlen("GATEWAY="));
            strcat(file_buf, buf);
        } else if (!strncmp(ptok, "ONBOOT=", strlen("ONBOOT=")))
            break ;
        ptok = strtok(NULL, "\n");
    }
    close(fd);
    return 0;
}

static int save_net_config(char recv_msg[])
{
    char    *ptok;
    int     file_len, fd, size_len;
    char    buf[64] = {0};
    char    net_dev[8] = {0};
    char    file_path[64] = {0};
    char    net_conf[256] = {0};

    memset(net_dev, 0x00, sizeof(net_dev));
    memset(net_conf, 0x00, sizeof(net_conf));
    memset(file_path, 0x00, sizeof(file_path));

    ptok = strtok(recv_msg, "\n");
    while (ptok != NULL) {
        memset(buf, 0x00, sizeof(buf));
        if (!strncmp(ptok, "dev=", strlen("dev="))) {
            sprintf(buf, "DEVICE=%s\n", ptok + strlen("dev="));
            strcat(net_conf, buf);
            strcpy(net_dev, ptok + strlen("dev="));
        } else if (!strncmp(ptok, "ip=", strlen("ip="))) {
            sprintf(buf, "IPADDR=%s\n", ptok + strlen("ip="));
            strcat(net_conf, buf);
        } else if (!strncmp(ptok, "mask=", strlen("mask="))) {
            sprintf(buf, "NETMASK=%s\n", ptok + strlen("mask="));
            strcat(net_conf, buf);
        } else if (!strncmp(ptok, "gateway=", strlen("gateway="))) {
            sprintf(buf, "GATEWAY=%s\n", ptok + strlen("gateway="));
            strcat(net_conf, buf);
        } else if (!strncmp(ptok, "broadcast=", strlen("broadcast="))) {
            sprintf(buf, "BROADCAST=%s\n", ptok + strlen("broadcast="));
            strcat(net_conf, buf);
        }
        ptok = strtok(NULL, "\n");
    }
    strcat(net_conf, "ONBOOT=yes");

    sprintf(file_path, "%s%s", NET_PATH, net_dev);
    if ((fd = open(file_path, O_WRONLY | O_TRUNC)) == -1) {
        loginf_out("系统管理者打开网络配置错误.");
        return -1;
    }

    file_len = strlen(net_conf);
    if ((size_len = write(fd, net_conf, file_len)) < file_len) {
        loginf_out("系统管理者修改网络配置错误.");
        return -1;
    }
    close(fd);

    return 0;
}

int shutdown_sys(int sock, char recv_msg[])
{
    loginf_out("系统管理者关闭机器!");
    system("shutdown -h now");
    return 0;
}

int restart_sys(int sock, char recv_msg[])
{
    loginf_out("系统管理者重启机器!");
    system("reboot");
    return 0;
}

int get_netconf(int sock, char recv_msg[])
{
    char    dev_buf[8] = {0};
    char    file_buf[256] = {0};

    sscanf(recv_msg + 2, "%[^\n]", dev_buf);

    if (read_net_config(file_buf, dev_buf) == -1)
        return -1;

    if (file_buf == NULL) {
        loginf_out("系统管理者获取网络配置读取文件错误.");
        return -1;
    }
    if (Send(sock, file_buf, strlen(file_buf), 0) == -1) {
        loginf_out("系统管理者获取网络配置发送数据错误.");
        return -1;
    }
    return 0;
}

int save_netconf(int sock, char recv_msg[])
{
    if (save_net_config(recv_msg) == -1) {
        Send(sock, SAVE_FAID, strlen(SAVE_FAID), 0);
        return -1;
    } else {
        if (Send(sock, SAVE_SCES, strlen(SAVE_SCES), 0) == -1)
            return -1;
        system("service network restart > /dev/null 2>&1");
    }
    return 0;
}

int get_systime(int sock, char recv_msg[]) 
{
    long int    tnow;
    char        tbuf[16] = {0};

    tnow = time(NULL);
    sprintf(tbuf, "%ld", tnow);
    loginf_out("系统管理者获取系统时间.");
    return Send(sock, tbuf, strlen(tbuf), 0);
}

int set_systime(int sock, char recv_msg[])
{
    char tbuf[64];

    loginf_out("系统管理者设置系统时间.");
    sprintf(tbuf, "date %s >/dev/null 2>&1", recv_msg + 2); // trim `cmd(0x0x)\n`
    system(tbuf);

    return 0;
}

int start_sshd(int sock, char recv_msg[])
{
    loginf_out("系统管理者开启sshd服务.");
    system("service sshd start >/dev/null 2>&1");
    return 0;
}

int stop_sshd(int sock, char recv_msg[])
{
    loginf_out("系统管理者关闭sshd服务.");
    system("service sshd stop >/dev/null 2>&1");
    return 0;
}

int get_sshdstatus(int sock, char recv_msg[])
{
    int     nf;
    char    sbuf[10] = {0};

    nf = open("/var/run/sshd.pid", O_RDONLY);
    if (nf == -1) {
        if (errno == ENOENT)
            memcpy(sbuf, SAVE_FAID, strlen(SAVE_FAID));
        else
            return -1;
    } else {
        memcpy(sbuf, SAVE_SCES, strlen(SAVE_SCES));
        close(nf);
    }

    loginf_out("系统管理者获取sshd状态.");
    return Send(sock, sbuf, strlen(sbuf), 0);
}

int get_cpu_mem_rate(int sock, char recv_msg[])
{
    int     fd;
    char    buf[32] = {0};
    char    rbuf[32] = {0};

    sprintf(buf, "sh %scpuage > %s", SYS_PATH, SYS_PATH"cm.txt");
    system(buf);
    memset(buf, 0x00, sizeof(buf));
    sprintf(buf, "rm -rf %s", SYS_PATH"cm.txt");

    fd = open(SYS_PATH"cm.txt", O_RDONLY);
    if (fd == -1) {
        system(buf);
        return -1;
    }
    if (read(fd, rbuf, sizeof(rbuf)) == -1) {
        close(fd);
        system(buf);
        return -1;
    }
    system(buf);
    close(fd);

    //loginf_out("系统管理者获取cpu内存速率.");
    return Send(sock, rbuf, strlen(rbuf), 0);
}


char* get_bufline(char *line, char *buf, char *pos_bufend)
{
    int     i = 0;
    int     len_buf = pos_bufend - buf;

    while ((buf[i] != '\n') && (i < len_buf) )
    {
        line[i] = buf[i];
        ++i;
    }
    line[i] = 0;
    if (i < len_buf)
        return buf + i + 1;
    else
        return 0;
}

void steal_line(char *buf, int buf_len, char *line, char *ip, char *mask)
{
    int     len_line;
    char    *p, *pstr, *pos_bufend;
    char    tmp[80] = {0};

    p = buf;
    pos_bufend = buf + buf_len;

    while ( (p = get_bufline(tmp, p, pos_bufend)) )
    {
        if (((pstr = strstr(tmp, ip)) != 0) &&
                (strstr(pstr, mask) != 0))
        {
            strcpy(line, tmp);
            len_line = strlen(tmp) + 1;
            memmove(p - len_line, p, pos_bufend - p);
            buf_len -= len_line;
            buf[buf_len] = 0;
            break;
        }
    }
}

size_t getfilesz(FILE* fp)
{
    struct stat fs;
    int fd = fp->_fileno;
    fstat(fd, &fs);
    return fs.st_size;
}

static int get_max_fip_idx(char *buf, int buf_len, char *flag)
{
    int     idx = -1;
    int     idx_max = -1;
    char    *p, *pos_bufend, *pfind;
    char    line[128] = {0};

    p = buf;
    pos_bufend = buf + buf_len;

    while ( (p = get_bufline(line, p, pos_bufend)) != 0)
    {
        if ( (pfind = strstr(line, flag)) != NULL )
        {
            if (sscanf(pfind + strlen(flag)+1, "%d", &idx) != 1)
                return 0;
            if (idx > idx_max)
                idx_max = idx;
        }
        memset(line, 0, sizeof(line));
    }

    return idx_max + 1;
}

static int get_float_ipmask(char *buf, char *ip, char *mask, char *ethVar, int* flag)
{
    char    *pcmd;
    char    cmd[1024] = {0};
    sprintf(cmd, "%s", buf);

    if ( (pcmd = strstr(cmd, "eth")) == NULL )
        return 0;

    sscanf(pcmd, "%[^#]", ethVar);
    if ( (pcmd = strstr(pcmd, "#")) != NULL )
        sscanf(pcmd+1, "%[^#]", ip);
    if ( (pcmd = strstr(pcmd+1, "#")) != NULL )
        sscanf(pcmd+1, "%[^\n]", mask);
    if (strstr(cmd, "up") != NULL){
        *flag = 1;}
    else if (strstr(cmd, "down") != NULL){
        *flag = 2;}

    return 1;
}

int is_in_config(char *buf, char* ip, char* mask, char* ethVar, int buf_len)
{
    char    tmp[80] = {0};
    char    *p = buf;
    char    *pstr = 0;
    char    *pos_bufend = buf + buf_len;

    while ((p = get_bufline(tmp, p, pos_bufend))){
        if ( ((pstr = strstr(tmp, ethVar)) != 0) &&
                ((pstr = strstr(tmp, ip)) != 0) &&
                (strstr(pstr, mask) != 0) ){
            return 1;
        }
    }

    return 0;
}

static int del_out_fip(char *ethVar, char *ip, char *mask)
{
    int     len, buf_len;
    int     idx = -1;
    FILE    *fp;
    char    *p, *pstr ,*bufend;
    char    runsh[128] = {0};
    char    line[256] = {0};
    char    delbuf[1024*10] = {0};

    system("ifconfig | grep \"eth\\|inet\"| grep -v \"127.0.0.1\" |grep -A1 \"eth0:\\|eth1:\" > .tmpfile");
    fp = fopen(".tmpfile", "r+");
    if ( (len = fread(delbuf, 1, sizeof(delbuf), fp)) <= 0)
        return 0;

    p = delbuf;
    buf_len = getfilesz(fp);
    bufend = delbuf + buf_len;

    while ( (p = get_bufline(line, p, bufend)) )
    {
        if ( (pstr = strstr(line, ethVar)) != NULL)
        {
            sscanf(pstr + strlen(ethVar) + 1, "%d", &idx);
            p = get_bufline(line, p, bufend);
            if(p == NULL)
                break;
            if ( (strstr(line, ip) != NULL) &&
                    (strstr(line, mask) != NULL) )
                break;
        }
    }

    sprintf(runsh, "ifconfig %s:%d %s netmask %s down\n", ethVar, idx, ip, mask);
    system(runsh);
    fclose(fp);
    unlink(".tmpfile");

    return 0;
}

int is_same_net(char *cmpip1, char *cmpmask1, char *cmpip2, char *cmpmask2)
{
    u32 ip1 = (inet_atoul(cmpip1) & inet_atoul(cmpmask1));
    u32 ip2 = (inet_atoul(cmpip2) & inet_atoul(cmpmask2));
    if (ip1 == ip2)
        return 1;

    return 0;
}

int del_same_netseg(char *buf, char *ethVar, char *ip, char *mask, int buf_len)
{
    int     retval;
    char    *p, *pstr, *pos_bufend;
    char    line[80] = {0};
    char    cmpip[128] = {0};
    char    cmpmask[128] = {0};

    p = buf;
    pos_bufend = buf + buf_len;

    while ( (p = get_bufline(line, p, pos_bufend)) )
    {
        if ((pstr = strstr(line, ethVar)) != NULL)
            sscanf(pstr, "%*s%s", cmpip);
        if ((pstr = strstr(line, "netmask")) != NULL)
            sscanf(pstr + 8, "%s", cmpmask);
        if ((retval = is_same_net(cmpip, cmpmask, ip, mask)) == 1)
            system(line);
    }

    return 0;
}

int get_cur_ipinfo(char *ip, char *mask, char *ethVar)
{
    char    *p = NULL;
    char    line[1024] = {0};
    int     linesz = 1024;
    FILE    *fp = NULL;

    system("ifconfig | grep \"eth\\|inet\" | grep -v \"127.0.0.1\" |grep -A1 \"eth0\\|eth1\" |grep -v \"eth0:\\|eth1:\" > .tmpfile1");
    fp = fopen(".tmpfile1", "r+");
    if (fp == NULL)
        return 0;

    while (feof(fp) == 0)
    {
        memset(line, 0x00, sizeof(line));
        fgets(line, linesz, fp);

        if (pre_deal_with_line(line) == NULL)
            continue;

        if ((p = strstr(line, "inetaddr:")) != NULL){
            sscanf(p+sizeof("inetaddr:")-1, "%[0-9.]", ip);
            p += sizeof("inetaddr:");
            if ((p = strstr(line, "Mask:")) != NULL){
                sscanf(p+sizeof("Mask:")-1, "%[0-9.]", mask);
                break;
            }
        }
    }

    fclose(fp);
    unlink(".tmpfile1");

    return 0;
}

int re_write_file(char *buf, char *fname)
{
    FILE* fp = fopen(fname, "w+");
    fwrite(buf, 1, strlen(buf), fp);
    fclose(fp);
    return 0;
}

int make_floatip_up(FILE *fp, char *ethVar, char *ip, char *mask, int fsz, char *buf, char *fname)
{
    int     inconfig, idx_max;
    char    runsh[128] = {0};
    char    shhead[128] = "#!/bin/bash\n";

    if (fsz == 0)
    {
        fwrite(&shhead, strlen(shhead), 1, fp);
        sprintf(runsh, "ifconfig %s:1 %s netmask %s up\n", ethVar, ip, mask);
        fwrite(&runsh, strlen(runsh), 1, fp);
        system(runsh);
        fclose(fp);
    }
    else
    {
        inconfig = is_in_config(buf, ip, mask, ethVar, fsz);
        if (inconfig == 1 )
            return 0;
        idx_max = get_max_fip_idx(buf, fsz, ethVar);
        sprintf(runsh, "ifconfig %s:%d %s netmask %s up\n", ethVar, idx_max, ip, mask);
        fwrite(&runsh, strlen(runsh), 1, fp);
        system(runsh);
        fclose(fp);
    }

    loginf_fmt("系统管理添加浮动ip：地址：%s ,掩码：%s.", ip, mask);

    return 0;
}

int make_floatip_down(FILE *fp, char *ethVar, char *ip, char *mask, int fsz, char *buf, char *fname)
{
    int     retval, inconfig;
    char    curip[64] = {0};
    char    curmask[64] = {0};
    char    *down_line = NULL;
    u32     str_len;

    get_cur_ipinfo(curip, curmask, ethVar);
    if (fsz == 0){
        del_out_fip(ethVar, ip, mask);
        if ((retval = is_same_net(ip, mask, curip, curmask)) == 0)
        {
            del_same_netseg(buf, ethVar, ip, mask, fsz);
            fclose(fp);

            re_write_file(buf, fname);
        }
        return 0;
    }
    else
    {
        inconfig = is_in_config(buf, ip, mask, ethVar, fsz);
        if (inconfig == 0 )
        {
            del_out_fip(ethVar, ip, mask);
            if ((retval = is_same_net(ip, mask, curip, curmask)) == 0)
            {
                del_same_netseg(buf, ethVar, ip, mask, fsz);
                fclose(fp);
                re_write_file(buf, fname);
            }
            return 0;
        }
        else
        {
            down_line = (char*)malloc(1024*sizeof(char));
            fseek(fp, 0L, SEEK_END);
            steal_line(buf, fsz, down_line, ip, mask);
            str_len = strlen(down_line);
            strreplace(&down_line, (char*)"up", (char*)"down", REPLACE_ONE, &str_len);
            system(down_line);
            if ((retval = is_same_net(ip, mask, curip, curmask)) == 0)
            {
                del_same_netseg(buf, ethVar, ip, mask, fsz);
                fclose(fp);
                re_write_file(buf, fname);
                system(buf);
            }
            oss_free((void*)&down_line);
        }
    }

    loginf_fmt("系统管理删除浮动ip: 地址：%s ,掩码：%s.", ip, mask);

    return 0;
}

int mod_floatip(int sock, char recv_msg[])
{
    int     fsz, retval;
    int     flag = -1;
    FILE    *fp;
    char    buf[1024 * 20] = {0};
    char    fname[256] = {0};

    char    ip[16] = {0};
    char    mask[16] = {0};
    char    ethVar[16] = {0};

    sprintf(fname, "%s/%s", DEFAULT_APP_DIR, ".floatip.conf");
    if ((fp = fopen(fname, "a+")) == NULL)
        return -1;

    fsz = getfilesz(fp);
    fread(buf, fsz, 1, fp);

    retval = get_float_ipmask(recv_msg+1, ip, mask, ethVar, &flag);
    if (retval == 0)
        return 0;

    switch (flag)
    {
        case 1:
            make_floatip_up(fp, ethVar, ip, mask, fsz, buf, fname);
            break;
        case 2:
            make_floatip_down(fp, ethVar, ip, mask, fsz, buf, fname);
            break;
    }

    return read_info(sock);
}

int query_floatip(int sock, char recv_msg[])
{
    char    cmd[128] = {0};
    sprintf(cmd, "sh %ssysif.sh gfi %s >%s", SYS_PATH, recv_msg + 2, TMP_PATH);
    system(cmd);

    return read_info(sock);
}

int tcp_link_con_test(char *tip, char *tport, char *tres)
{
    int     sockfd, retval;
    struct  sockaddr_in laddr;
    struct  timeval sendTimeOut = {3, 0};

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        return -1;

    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char*)&sendTimeOut, sizeof(sendTimeOut)) == -1)
        return -1;

    memset(&laddr, 0, sizeof(laddr));
    laddr.sin_family = AF_INET;
    laddr.sin_addr.s_addr = inet_addr(tip);
    laddr.sin_port = htons(atoi(tport));

    retval = connect(sockfd, (struct sockaddr*)&laddr, sizeof(laddr));
    if (retval == -1){
        if (errno == ECONNREFUSED)
        {
            sprintf(tres, "TCP:success:failed");
            return 0;
        }

        if (errno == EINPROGRESS || errno == ENETUNREACH || errno == EHOSTUNREACH)
        {
            sprintf(tres, "TCP:failed:failed");
            return 0;
        }
    }
    if (retval == 0){
        sprintf(tres, "TCP:success:success");
        return 0;
    }

    return 1;
}

int chk_mach_work_on(char *chk_ip)
{
    FILE    *fp;
    char    cmd[256] = {0};
    char    buf[1024] = {0};
    int     flag = 0;

    unlink(".ping_tmpfile");
    sprintf(cmd, "ping %s -c 3 -w 3 -l 1 > .ping_tmpfile ", chk_ip);
    system(cmd);

    fp = fopen(".ping_tmpfile", "r+");
    fread(buf, 1, sizeof(buf), fp);

    if (strstr(buf, " 100% packet loss") != NULL)
        flag = -1;

    fclose(fp);
    unlink(".ping_tmpfile");

    return  flag;
}

int chk_port_work_on(char *chk_ip, char *chk_port)
{   
    fd_set  rfds;
    char    buf[100] = "test";
    int     sockfd, retval, icmpsock;

    struct  sockaddr_in laddr;
    struct  ip *strip;
    struct  icmp *stricmp;
    struct  timeval tv;

    memset(&laddr, 0, sizeof(laddr));
    laddr.sin_family = AF_INET;
    laddr.sin_addr.s_addr = inet_addr(chk_ip);
    laddr.sin_port = htons(atoi(chk_port));

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        return -1;

    if ((icmpsock = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
        return -1;

    retval = sendto(sockfd, buf, 0, 0, (struct sockaddr*)&laddr, sizeof(laddr));

    FD_ZERO(&rfds);
    FD_SET(icmpsock, &rfds);
    tv.tv_sec = 2;
    tv.tv_usec = 0;

    retval = select(icmpsock+1, &rfds, NULL, NULL, &tv);
    if (retval <= 0){
        return 0;
    }

    if (FD_ISSET(icmpsock, &rfds))
        read(icmpsock, buf, 64);

    strip = (struct ip*)buf;
    if (strip->ip_p == IPPROTO_ICMP){
        stricmp = (struct icmp*)(buf + sizeof(struct ip));
        if (stricmp->icmp_type == ICMP_UNREACH){
            if (stricmp->icmp_code == ICMP_UNREACH_PORT)
                return -1;
        }
    }

    return 0;
}

int udp_link_con_test(char *chk_ip, char *chk_port, char *ures)
{
    int     ret;

    if ((ret = chk_mach_work_on(chk_ip)) == -1)
    {
        sprintf(ures, "UDP:failed:failed");
        return 0;
    }

    if ((ret = chk_port_work_on(chk_ip, chk_port)) == -1)
    {
        sprintf(ures, "UDP:success:failed");
        return 0;
    }
    else
    {
        sprintf(ures, "UDP:success:success");
        return 0;
    }

    return 0;
}

int parse_net_link_item(char *buf, char *pres)
{
    char    *p, *ppo;
    char    gid[64] = {0};
    char    gip[64] = {0};
    char    uport[64] = {0};
    char    tport[64] = {0};
    char    p_res[256] = {0};
    char    tres[128] = {0};
    char    ures[128] = {0};

    p = buf;
    sscanf(p, "%[^:]", gid);
    p += (strlen(gid) + 1);
    sscanf(p, "%[^:]", gip);
    p += (strlen(gip) + 1);

    if ((ppo = strstr(p, "UDP_")) != NULL)
    {
        sscanf(ppo + strlen("UDP_"), "%[0-9]", uport);
        udp_link_con_test(gip, uport, ures);
    }

    if ((ppo = strstr(p, "TCP_")) != NULL)
    {
        sscanf(ppo + strlen("TCP_"), "%[0-9]", tport);
        tcp_link_con_test(gip, tport, tres);
    }

    if ((strlen(ures) != 0) && (strlen(tres) != 0))
    {
        sprintf(p_res, "%s:%s,%s;", gid, tres, ures);
        loginf_fmt("系统管理检测网络链路连接: tcp 协议地址：%s, 端口：%s; udp 协议地址：%s 端口：%s.", gip, tport, gip, uport);
    }
    else
    {
        if (strlen(tres) != 0){
            sprintf(p_res, "%s:%s;", gid, tres);
            loginf_fmt("系统管理检测网络链路连接: tcp 协议地址：%s 端口：%s.", gip, tport);
        }

        if (strlen(ures) != 0){
            sprintf(p_res, "%s:%s;", gid, ures);
            loginf_fmt("系统管理检测网络链路连接: udp 协议地址：%s 端口： %s.", gip, uport);
        }
    }

    strncpy(pres, p_res, strlen(p_res));
    return 0;
}

int chk_net_link(int sock, char recv_msg[])
{
    char    *pTmp, *pChkItem;
    char    Lin_Res[128] = {0};
    char    Chk_Res[128] = {0};

    pTmp = strtok(recv_msg + 1, ";");
    while (pTmp != NULL)
    {
        pChkItem = pTmp;
        pTmp = strtok(NULL, ";");

        parse_net_link_item(pChkItem, Lin_Res);
        strcat(Chk_Res, Lin_Res);
        memset(Lin_Res, 0x00, sizeof(Lin_Res));
    }

    return Send(sock, Chk_Res, strlen(Chk_Res), 0);
}

int mon_sys_proc(int sock, char recv_msg[])
{
    int     ret;
    FILE    *fp;
    char    buf[1024] = {0};
    char    snddat[256] = {0};
    char    ferryt[32] = {0};
    char    ferryu[32] = {0};
    char    sysman[32] = {0};

    unlink(".monfile");
    system("ps -ef|grep vp-ferry|grep -v \"grep\" >> .monfile");
    system("ps -ef|grep sys-manager|grep -v \"grep\" >> .monfile");

    fp = fopen(".monfile", "r");
    fread(buf, 1, sizeof(buf), fp);

    if (strstr(buf, "sys-manager") != NULL)
        sprintf(sysman, SAVE_SCES);
    else
        sprintf(sysman, SAVE_FAID);

    if (strstr(buf, "vp-ferry -t") != NULL)
        sprintf(ferryt, SAVE_SCES);
    else
        sprintf(ferryt, SAVE_FAID);

    if (strstr(buf, "vp-ferry -u") != NULL)
        sprintf(ferryu, SAVE_SCES);
    else
        sprintf(ferryu, SAVE_FAID);

    sprintf(snddat, "%s:%s:%s", sysman, ferryt, ferryu);

    unlink(".monfile");
    fclose(fp);

    loginf_out("系统管理探测当前进程.");
    if ((ret = Send(sock, snddat, strlen(snddat), 0)) == -1)
        return -1;

    return 0;
}


struct __tms_reqst {
    int     reqst_cmd;
    int     (*deal_tms_reqst)(int sock, char recv_msg[]);
};

struct __tms_reqst tms_reqst[] = {
    {0 + REQ_BASENUM,  shutdown_sys},
    {1 + REQ_BASENUM,  restart_sys},
    {2 + REQ_BASENUM,  get_netconf},
    {3 + REQ_BASENUM,  save_netconf},
    {4 + REQ_BASENUM,  get_systime},
    {5 + REQ_BASENUM,  set_systime},
    {6 + REQ_BASENUM,  start_sshd},
    {7 + REQ_BASENUM,  stop_sshd},
    {8 + REQ_BASENUM,  get_sshdstatus},
    {9 + REQ_BASENUM,  get_cpu_mem_rate},
    {10 + REQ_BASENUM, get_sysinfo},
    {11 + REQ_BASENUM, get_sysinfo},
    {12 + REQ_BASENUM, get_sysinfo},
    {13 + REQ_BASENUM, get_meminfo},
    {14 + REQ_BASENUM, get_meminfo},
    {15 + REQ_BASENUM, get_diskinfo},
    {16 + REQ_BASENUM, get_diskinfo},
    {17 + REQ_BASENUM, get_diskinfo},
    {18 + REQ_BASENUM, get_sysinfo},
    {19 + REQ_BASENUM, get_netinfo},
    {20 + REQ_BASENUM, get_netinfo},
    {21 + REQ_BASENUM, get_netinfo},
    {22 + REQ_BASENUM, get_netinfo},
    {23 + REQ_BASENUM, get_sysinfo},
    {24 + REQ_BASENUM, get_meminfo},
    {25 + REQ_BASENUM, mod_floatip},
    {26 + REQ_BASENUM, query_floatip},
    {27 + REQ_BASENUM, chk_net_link},
    {28 + REQ_BASENUM, mon_sys_proc}
};

static int get_request_index(int cmd, struct __tms_reqst *rqst)
{
    int     idx = 0;
    while (idx < (int)(rtotal))
    {
        if (rqst[idx].reqst_cmd == cmd)
            break;
        ++idx;
    }

    if (idx == rtotal)
        idx = -1;

    return idx;
}

static int deal_system_request(int cli_socket, char recv_msg[])
{
    int     cmd, idx;

    cmd = (unsigned char)recv_msg[0];
    idx = get_request_index(cmd, tms_reqst);
    if (idx == -1)
        return -1;

    return tms_reqst[idx].deal_tms_reqst(cli_socket, recv_msg);
}

int main(int argc, char * argv[])
{
    int		    sockfd = -1;
    int		    cli_socket = -1;
    int		    len_recv = 0;
    char	    recv_buf[8*1024] = {0};
    struct      sockaddr_in local_addr;
    struct      sockaddr_in client_addr;

    int			reuse = 1;
    int			n_err_times = 0;
    int			opt = -1;
    bool		dbgmode = false;
    socklen_t	sin_size = sizeof(client_addr);

    while ((opt = getopt(argc, argv, "hvd")) != -1) 
    {
        switch (opt) 
        {
            case 'v':
                printf("%s Version %s\n", PROG_NAME, SYS_MANA_VER);
                return 0;
            case 'd':
                dbgmode = true;
                break ;
            case 'h':
            default:
                printf("Show help: %s -h\n", PROG_NAME);
                printf("Show version: %s -v\n", PROG_NAME);
                return 0;
        }
    }

    if ( ! dbgmode)
    {
        if (create_daemon() != 0)
            return 0;
    }

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        loginf_out("系统管理初始化socket网络错误."); 
        closelog();
        return -1;
    }

    if (setsockopt(sockfd,  SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == -1)
    {
        loginf_out("系统管理初始化网络设置地址复用错误.");
        closelog();
        return -1;
    }

    openlog("sys-manager", LOG_CONS|LOG_PID|LOG_PERROR, LOG_USER);
    if (__load_general_config() < 0)
	{
        loginf_out("初始化基本配置错误.");
        closelog();
        return -1;
    }

    memset(&client_addr, 0x00, sizeof(client_addr));
    memset(&local_addr, 0x00, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(__gg.sysmana_port);
    local_addr.sin_addr.s_addr = htonl(__gg.local_priv_addr);

	
    if (bind(sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr)) == -1) {
        loginf_out("系统管理初始化网络绑定错误.");
        closelog();
        return -1;
    }
    if (listen(sockfd, 5) == -1) {
        loginf_out("系统管理初始化网络监听错误.");
        closelog();
        return -1;
    }

    while (1)
    {
        if ((cli_socket = accept(sockfd, (struct sockaddr *)&client_addr, &sin_size)) == -1) {
            loginf_out("系统管理初始化网络获取客户端连接错误.");
            ++n_err_times;
            if (n_err_times > max_err_times)
                break;
        }
        n_err_times = 0;
        memset(recv_buf, 0x00, sizeof(recv_buf));
        if ( (len_recv = recv(cli_socket, recv_buf, sizeof(recv_buf), 0)) == -1) {
            loginf_out("系统管理网络接收数据错误.");
            close(cli_socket);
            continue ;
        }
        deal_system_request(cli_socket, recv_buf);
        close(cli_socket);
    }
    closelog();

    return 0;
}

