#include "common.h"
#include "license.h"

static bool g_cert_enable = false;
static void print_char(char ch);
static void dis_interpret(const unsigned char *buf, int len);
static const char *g_p_app_dir = DEFAULT_APP_DIR;

static void
print_char(char ch)
{
	if(isprint(ch))
		fputc(ch, stdout);
	else
		fputc('.', stdout);
}

static void dis_interpret(const unsigned char *buf, int len)
{
	printf("\t");
	int idx = 0;
	while (idx < len)
		print_char(buf[idx++]);
	printf("\n");
}

void _t_disbuf(const unsigned char *buf, int len)
{
	int idx = 0;
	int len_tail = len % 16;
	const unsigned char *tail = buf + (len / 16) * 16;

	while(idx + 16 <= len)
	{
		printf("%04x  ", idx);
		printf("%02x %02x %02x %02x %02x %02x %02x %02x - %02x %02x %02x %02x %02x %02x %02x %02x ",
				buf[idx], buf[idx+1], buf[idx+2], buf[idx+3], buf[idx+4], buf[idx+5], buf[idx+6], buf[idx+7],
				buf[idx+8], buf[idx+9], buf[idx+10], buf[idx+11], buf[idx+12], buf[idx+13], buf[idx+14], buf[idx+15]);
		dis_interpret(buf + idx, 16);
		idx += 16;
	}

	if (idx < len - 1)
	{
		printf("%04x  ", idx);
		idx = 0;
		while (idx < 16)
		{
			if (idx == 8)
				printf("- ");
			if (idx < len_tail)
				printf("%02x ", tail[idx]);
			else
				printf("** ");

			++idx;
		}
		dis_interpret(tail, len_tail);
	}
}

int Bind(int sockfd, struct sockaddr_in saddr, u32 socklen)
{
    int ret;

    ret = bind(sockfd, (struct sockaddr *)&saddr, socklen);
    if (ret < 0){
        syslog(LOG_INFO, "Bind() [%s:%d] error: %s",
                inet_ntoa(saddr.sin_addr), (u16)ntohs(saddr.sin_port), strerror(errno));
        return -1;
    }
    return 0;
}

int Connect(int sockfd, struct sockaddr *serv_addr, socklen_t addrlen, int tm_out)
{
    int ret = 0;
    unsigned long ul = 1;
    int error = -1;
    int len = sizeof(int);
    timeval tm;
    fd_set set;

    ioctl(sockfd, FIONBIO, &ul); //设置为非阻塞模式

    if ((ret = connect(sockfd, serv_addr, addrlen)) == -1)
    {
        //loginf_fmt("connect return -1 error is %s", strerror(errno));
        loginf_fmt("connect return -1 error is %s", strerror(errno));
        tm.tv_sec  = tm_out;
        tm.tv_usec = 0;
        FD_ZERO(&set);
        FD_SET(sockfd, &set);
        if (select(sockfd+1, NULL, &set, NULL, &tm) > 0)
        {
            getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, (socklen_t *)&len);
            if(error == 0) 
            {
               // loginf_out("select ok  > 0, error = 0");
                loginf_out("select ok  > 0, error = 0");
                ret = 0;
            }
            else 
            {
                ret = -1;
                //loginf_out("select ok  > 0, error = -1");
                loginf_out("select ok  > 0, error = -1");
            }
        } 
        else 
        {
            ret = -1;
            //loginf_out("select error  < 0, error = -1");
            loginf_out("select error  < 0, error = -1");
        }
    }
    //loginf_fmt("ret is %d", ret);
    loginf_fmt("ret is %d", ret);
    ul = 0;
    ioctl(sockfd, FIONBIO, &ul); //设置为阻塞模式

    //ret = connect(sockfd, serv_addr, addrlen);
    if (ret < 0) {
        syslog(LOG_INFO, "Connect() [%s:%d] error: %s",
                inet_ntoa(((SAI *)serv_addr)->sin_addr),
                ntohs(((SAI *)serv_addr)->sin_port), strerror(errno));
        return -1;
    }
    return 0;
}

int Accept(int s, struct sockaddr *addr, socklen_t *addrlen)
{
    int newfd = -1;

    if ((newfd = accept(s, addr, addrlen)) < 0)
	{
		if (errno != EAGAIN)
			syslog(LOG_INFO, "Accept() error: %s", strerror(errno));
	}

    return newfd;
}

int Send(int s, const void * buf, u32 len, int flags)
{
    int ret;
    u32 nsend = 0;
    u32 total = len;

    while (len > 0) {
        if ((ret = send(s, (void*)((unsigned long)buf + nsend), total - nsend, flags)) < 0) {
            if (errno != EPIPE)
                logerr_fmt("Send() error: [%d] %s", errno, strerror(errno));
            return -1;
        }
        nsend += ret;
        len -= nsend;
    }
    return nsend;
}

ssize_t Recvn(int fd, char *vptr, size_t n) 
{ 
	size_t  nleft; 
	ssize_t nread; 
	char   *ptr; 

	ptr = vptr; 
	nleft = n; 
	while (nleft > 0)
	{ 
		if ( (nread = recv(fd, ptr, nleft, 0)) < 0) 
		{ 
			return -1;
		}
		else if (nread == 0)
		{
			return 0; 
		}
		nleft -= nread; 
		ptr += nread; 
	}
	return n - nleft;
}

int Recv(int s, void * buf, u32 len, int flags)
{
    int ret = -1;

    if ((ret = recv(s, buf, len, flags)) < 0) 
    {
        if (errno != ECONNRESET)
            syslog(LOG_INFO, "recv() error :%s", strerror(errno));
    }

    return ret;
}

/*
 * return value: -1 if failed, 1 if success
 */

int recv_tail(int sockfd, int extlen, char **ut_buf, u32 *pack_len)
{
	if (extlen < 0)
		return -1;
	else if (extlen == 0)
		return 1;

	int res = -1;
	int nleft = 0;
	int nrecv = 0;
	char *pTmp = NULL;

    //printf("recv_tail: size -- %d -- \n", *pack_len + extlen);
	if ((pTmp = (char*)realloc(*ut_buf, *pack_len + extlen)) == NULL)
    {
        logdbg_fmt("recv_tail: realloc failed! size:%d", *pack_len + extlen);
		return -1;
    }
	*ut_buf = pTmp;

	// use pTmp for another memory
	pTmp = *ut_buf + *pack_len;
	nleft = extlen;
	while (nleft > 0)
	{
		nrecv = recv(sockfd, pTmp, nleft, 0);
		if (nrecv < 0)
			break;
        else if (nrecv == 0)
            return 0;
		pTmp += nrecv;
		*pack_len += nrecv;

		nleft -= nrecv;
	}

	if (nleft == 0)
		res = 1;

	return res;
}

int recv_until_close(int sockfd, char **ut_buf, u32 *pack_len)
{
	char buf[1024*5] = {0};
	int nRecv = 0;
	u32 len_infact = *pack_len;
	char *ptr_new = *ut_buf;

	while ((nRecv = Recv(sockfd, buf, sizeof(buf), 0)) > 0)
	{
		if (*pack_len + nRecv > len_infact)
		{
			len_infact = 2 * (*pack_len + nRecv);
			ptr_new = (char*)realloc(*ut_buf, len_infact);
			if (ptr_new == NULL)
			{
				logdbg_fmt("recv_until_close: realloc failed! size:%d\n", *pack_len + nRecv);
				break;
			}
			*ut_buf = ptr_new;
		}

		memcpy(*ut_buf + *pack_len, buf, nRecv);
		*pack_len = *pack_len + nRecv;
	}

	return (nRecv < 0) ? -1:1;
}

int  recv_until_end_flag(int sockfd, const char *flg, int len_flg, char **ut_buf, u32 *pack_len)
{
    char buf[1024 * 5] = {0};
    char *ptr_new = NULL;
    int nRecv = 0;

	puts("x 1");
	while ((nRecv = Recv(sockfd, buf, sizeof(buf), 0)) > 0)
    {
        printf("recv_until_end_flag nRecv:%d\n", nRecv);
		//printf("tail:\n");
		//t_disbuf(buf, nRecv);
        if ((ptr_new = (char*)realloc(*ut_buf, *pack_len + nRecv)) == NULL)
        {
            logdbg_fmt("recv_until_end_flag: realloc failed! size:%d\n", *pack_len + nRecv);
            return -1;
        }
        *ut_buf = ptr_new;
        memcpy(*ut_buf + *pack_len, buf, nRecv);
        *pack_len = *pack_len + nRecv;

        if (memcmp(*ut_buf + (*pack_len - len_flg), flg, len_flg) == 0)
            break;
    }
	t_disbuf(*ut_buf, *pack_len);
    printf("recv_until_end_flag end =======================\n");

    return 1;
}

int  recv_until_flag(int sockfd, const char *flg, int len_flg, char **ut_buf, u32 *pack_len)
{
    const char *pFlg = NULL;
	char buf[1024 * 5] = {0};
	char *ptr_new = NULL;
    char *pRecv = NULL;
	int nRecv = 0;
    int size_new = 0; 

    pFlg = flg;
    pRecv = buf;
	while ((nRecv = Recv(sockfd, pRecv, 1, 0)) == 1)
	{
        if (*pRecv == *pFlg) 
        {
            ++pFlg;
            // find flag
            if (pFlg - flg == len_flg)
            {
                size_new = *pack_len + (pRecv - buf) + 1;
                ptr_new = (char*)realloc(*ut_buf, size_new);
                if (ptr_new == NULL)
                {
                    logdbg_fmt("recv_until_flag: realloc failed 1! size:%d\n", size_new);
                    return -1;
                }

                *ut_buf = ptr_new;
                memcpy(*ut_buf + *pack_len, buf, (pRecv - buf) + 1);
                *pack_len = size_new;
                break;
            }
        }
        else
        {
            pFlg = flg;
        }
        ++pRecv;
	}
	return (nRecv <= 0) ? -1:1;
}

int Select(int nfds, fd_set * rfds, fd_set * wfds, fd_set * efds, struct timeval * tout)
{
    int retval = -1;

    retval = select(nfds + 1, rfds, wfds, efds, tout);
    if (retval == -1) {
        syslog(LOG_INFO, "Select() error: %s", strerror(errno));
        return -1;
    }

    return retval;
}

u16 getsockport(int sockfd)
{
    SAI       laddr;
    socklen_t len;
    u16       xport;

    memset(&laddr, 0x00, sizeof(laddr));
    len = sizeof(laddr);

    if (getsockname(sockfd, (struct sockaddr *)&laddr, &len) == -1)
        return 0;

    xport = ntohs(laddr.sin_port);
    return xport;
}

int noblock_accept(int fd, SA * paddr, int addrlen, const int time_out)
{
    int    ret;
    int    newfd;
    fd_set rfds;
    struct timeval tv;

    if (setnonblocking(fd) < 0)
        return -1;

    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);

    tv.tv_sec = time_out;
    tv.tv_usec = 0;

    ret = Select(fd, &rfds, NULL, NULL, &tv);
    if (ret <= 0)
        return ret;

    if (FD_ISSET(fd, &rfds)) {
        newfd = accept(fd, paddr, (unsigned int*)&addrlen);
        return newfd;
    }
    return 0;
}

int Setsockopt(int sock, int level, int optname)
{
    int ret = 1;
    int reuse = 1;

    ret = setsockopt(sock, level, optname, (const char *)&reuse, sizeof(reuse));
    if (ret < 0)
        syslog(LOG_INFO, "Setsockopt() error: %s", strerror(errno));

    return ret;
}

int
set_sock_timeout(int sockfd, int rTenthSec, int sTenthSec)
{
	const static int microSec_per_tenthSec= 1000*100;
	struct timeval tout = {0,0};

	if (rTenthSec > 0)
	{
		tout.tv_sec = rTenthSec/10;
		tout.tv_usec = rTenthSec%10 * microSec_per_tenthSec;
		if ( setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&tout, sizeof(struct timeval)) < 0)
			return -1;
	}

	if (sTenthSec > 0)
	{
		tout.tv_sec = sTenthSec/10;
		tout.tv_usec = sTenthSec%10 * microSec_per_tenthSec;
		if ( setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char*)&tout, sizeof(struct timeval)) < 0)
			return -1;
	}

	return 1;
}

void init_sockaddr(SAI *sockaddr, u32 ip, u16 port)
{
    memset(sockaddr, 0x00, sizeof(SAI));
    sockaddr->sin_family = AF_INET;
    sockaddr->sin_addr.s_addr = htonl(ip);
    sockaddr->sin_port = htons(port);
}

void close_sock(int *sock)
{
    if (*sock > 0) {
        close(*sock);
        *sock = -1;
    }
}

/*
void init_find(find_mem *fmem)
{
    if(fmem != NULL)
        memset(fmem, 0, sizeof(find_mem));
}

void reset_loop_find(find_mem *fmem, bool head)
{
    if (fmem == NULL)
        return;

    if (head)
        fmem->loop_cur = fmem->fnd_pos;
    else
        fmem->loop_cur = fmem->fnd_pos_tail;
}

char *loop_find(find_mem *fmem)
{
    char *ppos = NULL;

    if (fmem == NULL)
        return NULL;

    if (fmem->loop_cur != NULL)
    {
        ppos = fmem->loop_cur->pos;
        fmem->loop_cur = fmem->loop_cur->next;
    }

    return ppos;
}

char *loop_find_back(find_mem *fmem)
{
    char *ppos = NULL;

    if (fmem == NULL)
        return NULL;

    if (fmem->loop_cur != NULL)
    {
        ppos = fmem->loop_cur->pos;
        fmem->loop_cur = fmem->loop_cur->prev;
    }

    return ppos;
}

void add_find(find_mem *fmem, char *pfind)
{
    if (fmem == NULL)
        return;

    find_pos *pos = fmem->fnd_pos_tail;

    if (pos != NULL)
    {
        //while (pos->next != NULL)
         //   pos = pos->next;
        pos->next = (find_pos*)malloc(sizeof(find_pos));
        if (pos->next == NULL)
            return;
        pos->next->prev = pos;
        pos = pos->next;

        pos->pos = pfind;
        pos->next = NULL;
        fmem->fnd_pos_tail = pos;
    }
    else
    {
        fmem->fnd_pos = fmem->fnd_pos_tail = pos = (find_pos*)malloc(sizeof(find_pos));
        if (pos == NULL)
            return;
        fmem->loop_cur = pos;
        pos->pos = pfind;
        pos->prev = NULL;
        pos->next = NULL;
    }
    ++fmem->nfind;
}

void clr_find(find_mem *fmem)
{
    find_pos *pos = fmem->fnd_pos;
    find_pos *tmp = NULL;

    while (pos != NULL)
    {
        tmp = pos;
        pos = pos->next;

        oss_free(&tmp);
    }
    fmem->fnd_pos = NULL;
}
*/

/*
 * describe: replace string from src to dst, in range pos_b to pos_e in buffer *content.
 * arguments: 
 *  times: finger out replace times. set as -1 if replace all appeared.
 * return value: replace times. if -1 some error occured. if 0 none is matched. 
 */
int strreplace_pos(char *pos_b, char *pos_e, char **content, char *src, char *dst, int times, u32 *len)
{
    if ((src == NULL) || (dst == NULL))
        return -1;
    return memreplace_pos(pos_b, pos_e, content, len, times, src, strlen(src), dst, strlen(dst));
}

int memreplace_pos(char *pos_b, char *pos_e, char **content, u32 *len, int times, char *src, int nsrc, char *dst, int ndst)
{
    find_mem fmem;
    char *pfind = NULL;
    char *pnewbuf = NULL;
    int newbuflen = 0;
    char *pos = NULL;
    char *pos_last = NULL;
    char *ptmp = NULL;
    char *ptail = NULL;

    if (content == NULL || *content == NULL || len == NULL)
        return -1;
    ptail = *content + *len;

    //puts("rep 1");
    if (pos_b == NULL)
        pos_b = *content;
    if (pos_e == NULL)
        pos_e = ptail;
    if (pos_e < pos_b)
        return -1;
    if ( ((u32)(pos_b - *content) > *len) || ((pos_b - *content) < 0) )
        return -1;
    if ( ((u32)(pos_e - *content) > *len) || ((pos_e - *content) < 0) )
        return -1;

    //puts("rep 2");
    init_find(&fmem);
    pos = pos_b;
    while (times != 0)
    {
        //puts("----- 1");
        pfind = pos = (char*)memmem(pos, ptail - pos, src, nsrc);
        //puts("----- 2");
        if (pfind != NULL)
        {
            if (pfind > pos_e)
                break;
            add_find(&fmem, pfind);
        }
        pos += nsrc;
        if ( (pos >= pos_e) || ((*content - pos) > nsrc) )
            break;
        //puts("----- 3");
        if (times > 0)
            --times;
    }
        //puts("----- 4");
    if (fmem.nfind == 0)
        return 0;
    pos = NULL;
    newbuflen = *len + (ndst - nsrc) * fmem.nfind;

    //puts("rep 3");
#if 0
    printf("new len:%d, nsrc:%d, ndst:%d\n", newbuflen, nsrc, ndst);
#endif

    if (nsrc == ndst)
    {
    //puts("rep 4");
        pnewbuf = *content;
        while ( (pos = loop_find(&fmem)) != NULL)
            memcpy(pos, dst, ndst);
    }
    else
    {
    //puts("rep 5");
        if (oss_malloc(&pnewbuf, newbuflen + 1) < 0)
        {
            clr_find(&fmem);
            return -1;
        }
        ptmp = pnewbuf;
        pos_last = *content;
        while ( (pos = loop_find(&fmem)) != NULL)
        {
            memcpy(ptmp, pos_last, pos - pos_last);
            ptmp += pos - pos_last;
            pos_last += pos - pos_last;

            memcpy(ptmp, dst, ndst);
            ptmp += ndst;
            pos_last += nsrc;
        }
        memcpy(ptmp, pos_last, ptail - pos_last); 
        pnewbuf[newbuflen] = 0;

        oss_free(content);
        *content = pnewbuf;
        *len = newbuflen;
    }
    //puts("rep 6");
    clr_find(&fmem);

    return fmem.nfind;
}

int strreplace(char **content, char *src, char *dest, int times, u32 *len)
{
    int  ns = 0;
    int  nd = 0;
    int  nt = 0;
    int  range = 0;
    char *ps;
    char *pe;
	int num = 0;

    if (!strcmp(src, dest))
        return 1;

    ns = strlen(src);
    nd = strlen(dest);
    range = nd - ns;

    if (range > 0) {
        ps = strstr(*content, src);
        while (ps != NULL) {
            nt += range;
            ps += ns;
            ps = strstr(ps, src);
        }
        if ((*content = (char*)realloc(*content, *len + nt + 1)) == NULL)
            return -1;
    }

    ps = strstr(*content, src);
    pe = *content + *len;

    while (ps != NULL) {
        memmove(ps + nd, ps + ns, pe - ps - ns + 1);
        memcpy(ps, dest, nd);
        ps += nd;
        ps = strstr(ps, src);
        pe += range;
        *len += range;
		num += 1;

        if (times == REPLACE_ONE)
            break ;
    }
    *pe = 0x00;

    return num;
}

int strreply(char **content, char *src, char *dest, int replace_times, u32 *pack_len)
{
    return strreplace(content, src,dest, replace_times, pack_len);
}

/*
int replace_http_host(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    char sl[32] = {0};
    char sd[32] = {0};
    char host[64] = {0};
	char *ptr = NULL;
	int len = 0;

    inet_ultoa(put->lip, sl);
    inet_ultoa(put->dip, sd);

    sprintf(host, "%s:%d", sl, put->lport);

    if ((ptr = strnstr(*ut_buf, "Host: ", *pack_len, true)) != NULL)
	{
		ptr += (sizeof("Host: ") - 1);
		len = (*pack_len - (ptr - *ut_buf));
		if (len < sizeof("xxx.xxx.xxx.xxx") - 1)
			return 0;
		if ((ptr = strnstr(ptr, sl, sizeof("xxx.xxx.xxx.xxx") - 1, true)) == NULL)
			return 0;

        strreply(ut_buf, host, sd, REPLACE_ONE, pack_len);
    }
    return 0;
}
*/


static bool
match_char(char ch1, char ch2, bool sensitive)
{
    if ( ! sensitive)
    {
        int dis = 'a' - 'A';
        if ( ch2 >= 'a' && ch2 <= 'z')
            return (ch1 == ch2) || (ch1 == ch2 - dis);
        else if (ch2 >= 'A' && ch2 <= 'Z')
            return (ch1 == ch2) || (ch1 == ch2 + dis);
    }

    return ch1 == ch2;
}

char*
strnstr(const char *haystack, const char *needle, int max_len, bool sensitive) 
{
    if (haystack == NULL || needle == NULL)
        return NULL;

    const char *tmp = needle;
    const char *rem_pos = haystack;
    max_len = (max_len < 0 ? (int)((unsigned int)(~0) >> 1) : max_len);
    int rem_len = max_len;
    while ((*haystack != '\0') && (max_len != 0))
    {
        tmp = needle;
        rem_pos = haystack;
        rem_len = max_len;

        while ((*tmp != '\0') && (max_len-- > 0))
        {
            if ( ! match_char(*haystack, *tmp, sensitive) )
                break;
            ++haystack;
            ++tmp;
        }
        if (*tmp == '\0')
            break;
        haystack = rem_pos + 1;
        max_len = rem_len - 1;
        rem_pos = NULL;
    }

    return (char*)rem_pos;
}

bool 
strncmp_sen(char *s1, char *s2, int n, bool sensitive)
{
    if ( ! sensitive)
    {
        while ( (*s1 != 0) && n)
        {
            if ( ! match_char(*s1, *s2, sensitive))
                break;
            ++s1;
            ++s2;
            --n;
        }

        if ( n > 0 && (*s1 != 0 || *s2 != 0))
            return false;

        return true;
    }

    return (strncmp(s1, s2, n) == 0);
}

void kill_process()
{
    char buf[6];

    sprintf(buf, "kill %d >/dev/null 2>&1", getpid());
    system(buf);
}

int set_limit()
{
    int    fd = 0;
    struct rlimit rlim;

    getrlimit(RLIMIT_NOFILE , &rlim);

    rlim.rlim_cur = rlim.rlim_max = FD_MAXSIZE;
    fd = setrlimit(RLIMIT_NOFILE , &rlim);
    if (fd < 0) {
        syslog(LOG_INFO, "set_limit() failed");
        return -1;
    }
    return 0;
}

int vpprintf(const char * msg, ...)
{
    int     rv = 0;
    va_list arg;

    va_start(arg, msg);
    rv = vfprintf(stdout, msg, arg);
    va_end(arg);

    return rv;
}

void __oss_free(void **p)
{
    if (*p) {
        free(*p);
        *p = NULL;
    }
}

int __oss_malloc(void **p, int size)
{
    if ((*p = (void *)malloc(size)) == NULL) {
        //syslog(LOG_INFO, "oss_malloc() failed");
        logdbg_out("oss_malloc() failed!");
        return -1;
    }
    memset(*p, 0x00, size);
    return 0;
}

pid_t create_daemon()
{
    int   i;
    pid_t pid;

    if ((pid = fork()) != 0)
        return pid;

    if (setsid() < 0)
        return -1;

    for (i = 0; i < MAXFD; i++)
        close(i);

    chdir("/");
    open("/dev/null", STDIN_FILENO);
    open("/dev/null", STDOUT_FILENO);
    open("/dev/null", STDERR_FILENO);

    return pid;
}

int Hex2Int(const char * str)
{
    int result = 0;

    while (*str != '\0') {
        switch (*str) {
            case '0'...'9':
                result = result * 16 + *str - '0';
                break;
            case 'a'...'f':
                result = result * 16 + *str - 'a' + 10;
                break;
            case 'A'...'F':
                result = result * 16 + *str - 'A' + 10;
                break;
            default:
                return -1;
                break;
        }
        str++;
    }
    return result;
}

/*
 * @ Function: create only of share memory psmid,
 * @ it be used for run video stream proxy,
 * @ the every proxy is a daemon process.
 */
int get_sharemem_pid()
{
    struct timeval tv;
    struct timezone tz;

    gettimeofday(&tv, &tz);

    return tv.tv_sec/tv.tv_usec + tv.tv_sec%tv.tv_usec;
}

/*
 * @ proto_type: the proxy type of raw-vsudp or raw-vstcp
 * @ arg: the param of pass videostream process.
 */
int start_vstream_proxy(char * proto_type, char * arg[])
{
    pid_t pid;
    char  exec_path[128];

    //sprintf(exec_path, "%s/%s", DEFAULT_APP_DIR, proto_type);
    sprintf(exec_path, "%s/%s", g_p_app_dir, proto_type);

    signal(SIGCHLD, SIG_IGN);

    if ((pid = create_daemon()) < 0)
        _exit(-1);
    else if (pid == 0) {
        if (execv(exec_path, arg) == -1) {
            syslog(LOG_INFO, "start_vstream_proxy() failed");
            return -1;
        }
    }

    return pid;
}

int set_webbrowser_nocache(char **reqst, int *pack_len)
{
    int  len;
    int  dlen;
    char *pr = NULL;
    char *pa = NULL;
    char *pc = NULL;
    char cache[64] = {0};

    pa = strstr(*reqst, "Pragma");
    pc = strstr(*reqst, "Cache-Control");
    pr = strstr(*reqst, "\r\n\r\n");

    if (pr != NULL && pa == NULL && pc == NULL) {
        sprintf(cache, "\r\nPragma: %s\r\nCache-Control: %s", "no-cache", "no-cache");
        len = strlen(cache);
        dlen = *pack_len - (pr - *reqst);

        *reqst = (char*)realloc(*reqst, *pack_len + len);
        pr = strstr(*reqst, "\r\n\r\n");
        if (*reqst == NULL)
            return -1;

        if (dlen != 0) {
            memmove(pr + len, pr, dlen);
            memcpy(pr, cache, len);
            *pack_len += len;
        }
    }
    return 1;
}

/*
 * @ describe: get a key from a string
 * @ key: ip or port or other number
 * @ seg: begin of string
 */
int parse_key(char **ut_buf, char *key, char *seg)
{
    char *p;

    p = strstr(*ut_buf, seg);
    if (p != NULL)
        sscanf(p + strlen(seg), "%[0-9.]", key);
    else {
        syslog(LOG_INFO, "Not Found Key [%s]", seg);
        return -1;
    }
    return 1;
}

int get_content_len(char *buf, u32 len)
{
	char * p = NULL;
    char   olen[32] = {0};

    if ((p = strstr(buf, "Content-Length:")) == NULL)
        return -1;
    sscanf(p + strlen("Content-Length: "), "%[^\r\n]", olen);

	return atoi(olen);
}

int get_content_len_http(char *buf, u32 len)
{
	char * p = NULL;
    char   olen[32] = {0};

    if ((p = strstr(buf, "Content-Length:")) == NULL)
        return -1;
    sscanf(p + strlen("Content-Length: "), "%[^\r\n]", olen);

	return atoi(olen);
}

int get_content_len_osp(char *pkg,int start_pos)
{
	int len = 0;
    u16 inet_len_msg = 0;
    u16 host_len_msg = 0;

    memcpy(&inet_len_msg, pkg+start_pos, 2);
    len = host_len_msg = ntohs(inet_len_msg);
	
    return len;
}

void update_content_len(char **ut_buf, u32 *pack_len)
{
    char * p;
    char   olen[32];
    char   slen[64];
    char   dlen[64];
    int    nlen;

    if ((p = strstr(*ut_buf, "Content-Length:")) == NULL)
        return ;

    sscanf(p + strlen("Content-Length: "), "%[^\r\n]", olen);
    if (atoi(olen) == 0)
        return ;

    p = strstr(*ut_buf, "\r\n\r\n");
    nlen = *pack_len - (p - *ut_buf) - 4;
    sprintf(slen, "Content-Length: %s", olen);
    sprintf(dlen, "Content-Length: %d", nlen);
    strreply(ut_buf, slen, dlen, REPLACE_ONE, pack_len);
}

int create_pid_file(const char * pid)
{
    int  fd = -1;
    char fpath[64];
    char process_id[8];

    sprintf(process_id, "%d", getpid());
    sprintf(fpath, "%s/%s", PRO_PID_PATH, pid);

    if ((fd = open(fpath, O_APPEND)) < 0) {
        if (errno == ENOENT) {
            if ((fd = creat(fpath, S_IRWXU)) < 0)
                return -1;
            write(fd, process_id, strlen(process_id));
            close(fd);
            return 1;
        }
    }
    close(fd);
    return -1;
}

int remove_pid_file(const char * pid)
{
    char fpath[32];

    sprintf(fpath, "%s/%s", PRO_PID_PATH, pid);

    if (strlen(pid) > 0) {
        if (remove(fpath) < 0)
            return -1;
    }
    return 0;
}

int __fread(void *ptr, size_t size, size_t n, FILE *fp)
{
    fread(ptr, size, n, fp);
    if (ferror(fp)) {
        clearerr(fp);
        return -1;
    }
    return 0;
}

int __fwrite(const void *ptr, size_t size, size_t n, FILE *fp)
{
    fwrite(ptr, size, n, fp);
    if (ferror(fp)) {
        clearerr(fp);
        return -1;
    }
    return 0;
}

char * inet_ultoa(u32 u, char * s)
{
    static char ss[20];

    if (s == NULL)
        s = ss;
    sprintf(s, "%d.%d.%d.%d",
            (unsigned int)(u>>24)&0xff, (unsigned int)(u>>16)&0xff,
            (unsigned int)(u>>8)&0xff, (unsigned int)u&0xff);
    return s;
}

u32 inet_atoul(const char * s)
{
    int i;
    int u[4];
    u32 rv;

    if(sscanf(s, "%d.%d.%d.%d", &u[0], &u[1], &u[2], &u[3]) == 4) {
        for (i = 0, rv = 0; i < 4; i++) {
            rv <<= 8;
            rv |= u[i] & 0xff;
        }
        return rv;
    } else
        return 0xffffffff;
}

int setnonblocking(int sockfd)
{
    if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFD, 0)|O_NONBLOCK) == -1)
        return -1;
    return 0;
}

char*
trim(char *str)
{
	if (str == NULL)
		return NULL;

	char *base = str;
	char *curr = str;
	while (*curr != '\0')
	{
		if (isspace(*curr))
		{
			++curr;
			continue;
		}
		*base++ = *curr++;
	}
	*base = '\0';

	return str;
}

char*
trimleft(char *str)
{
	if (str == NULL)
		return NULL;

	char *curr = str;
	while (*curr != '\0')
	{
		if (isspace(*curr))
		{
			++curr;
			continue;
		}
		break;
	}
	strcpy(str, curr);

	return str;
}

char *
trimright(char *str)
{
	if (str == NULL)
		return NULL;

	char *valid_tail = str;
	char *curr = str;
	while (*curr != '\0')
	{
		if ( ! isspace(*curr))
			valid_tail = curr;
		++curr;
	}
	*(valid_tail + 1) = '\0';

	return str;
}

char * __strtrim(char * s)
{
    int i;
    int len;

    if (!s)
        return NULL;

    len = strlen(s);
    for (i = 0; i < len && isspace(s[i]); i++);
        memmove(s, s + i, len - i + 1);

    len = strlen(s);
    for (i = len - 1; i >= 0 && isspace(s[i]); i--)
        s[i] = '\0';

    return s;
}

int load_proxy_config(const char *config_name, int pmid, int proxy_sign, char value[C_TOTAL][32])
{
	const static char FLG_PLATFORM_CONF[] = "platform=";
	int i = 0;
	int ret = 1;
	query_conf *pconf = NULL;
	query_conf *pplatform = NULL;
	char cfg_path[256] = {0};
	char plat_flg[32] = {0};
	char *val = NULL;

	sprintf(cfg_path, "%s/%s", PLATFORM_CONFIG_DIR, config_name);
	sprintf(plat_flg, "%s%d", FLG_PLATFORM_CONF, pmid);

	if ((pconf = load_configuration(cfg_path)) == NULL)
	{
        //printf("open conf file:%s\n", cfg_path);
        loginf_out("读取平台配置失败!");
        return -1;
	}

	if ((pplatform = find_label(pconf, plat_flg)) == NULL)
	{
		free_configuration(&pconf);
		loginf_fmt("没有平台ID为[%d]的配置项", pmid);
		return -1;
	}

	for (i = 0; i < C_TOTAL; ++i)
	{
		memset(value[i], 0, sizeof(value[i]));
		if (proxy_sign == PROXY_AUTH_SERVER && i == L_VIDEOIP)
			break;
		if ((val = get_value_from_label(pplatform, m_conf_key[i])) == NULL)
		{
			loginf_fmt("缺少配置项\"%s\"", m_conf_key[i]);
			ret = -1;
			break;
		}
		strcpy(value[i], val);
	}
	free_configuration(&pconf);

    return ret;
}

void getsubstring(char *str, char a[][MAX_ARRAY], char seg)
{
    int  i = 0;
    char *p, *q;

    q = p = str;
    while (1) {
        if (*p == seg) {
            memcpy(a[i], q, p - q);
			a[i++][p-q] = 0;
            q = ++p;
        }
        if (*p++ == '\0') {
            memcpy(a[i], q, p - q);
            break ;
        }
    }
}

char * get_virtual_cameraid(char * cameraid)
{
    u32 ntime;

    ntime = time(NULL);
    sprintf(cameraid, "%d", rand_r(&ntime));
    return cameraid;
}

long
start_license(void(*before_exit)(int))
{
    /*
    struct li_arg *la = (struct li_arg*)malloc(sizeof(struct li_arg));
    memset(la, 0, sizeof(struct li_arg));
    la->exit_code = -20;
    la->before_exit = before_exit;
    sprintf(la->li_path, "%s/%s", DEFAULT_APP_DIR, "license");
    */

    unsigned long lipid = -1;
   /*
    if (pthread_create(&lipid, 0, li_mod, (void*)la) != 0)
        return -1;
        */
    return lipid;
}

bool read_cert(char * buf, int len)
{
    FILE * pf;
    char   path[64];

    sprintf(path, "%s/cert_user.conf", "/topconf/topvp");

    if ((pf = fopen(path, "rb")) == NULL) {
        syslog(LOG_INFO, "open user cert failed");
        return false;
    }

    if (__fread(buf, len, 1, pf) < 0) {
        fclose(pf);
        syslog(LOG_INFO, "read user cert failed");
        return false;
    }
    fclose(pf);

    return true;
}

bool load_user_cert()
{
    char * p;
    char   flag[2];
    char   buf[1024];

    memset(buf, 0x00, sizeof(buf));

    if (!read_cert(buf, sizeof(buf)))
	{
		loginf_out("证书检测: 读取证书配置失败!");
        return false;
	}

    if ((p = strstr(buf, "flag")) == NULL)
	{
		loginf_out("证书检测: 证书配置文件格式错误!");
        return false;
	}

    sscanf(p + sizeof("flag=")-1, "%[^\n]", flag);

    if (atoi(flag) == N_LOAD)
        return false;

	g_cert_enable = true;

    return true;
}

bool test_user_cert(SAI cli_addr)
{
    char sip[16] = {0};
    char buf[1024] = {0};

    if ( ! g_cert_enable)
        return true;

    inet_ntop(AF_INET, &(cli_addr.sin_addr), sip, 15);

    if ( ! read_cert(buf, sizeof(buf)))
    {
        loginf_out("证书检测: 读取证书状态失败!");
        return false;
    }

    if (strstr(buf, sip) == NULL)
        return false;

    return true;
}

bool cert_is_enable()
{
    return g_cert_enable;
}

int get_user_id(SAI cliaddr, char *userid)
{
    char *cliip;
    char *pstr;
    char buf[1024];
    char key[128];

    if (!g_cert_enable)
        return 1;

    if (userid == NULL)
        return -1;

    cliip = inet_ntoa(cliaddr.sin_addr);

    if (!read_cert(buf, sizeof(buf)))
        return -1;

    if ((pstr = strstr(buf, cliip)) == NULL)
        return -1;
    sscanf(pstr, "%[^\n]", key);

    if ((pstr = strrchr(key, '_')) == NULL)
        return -1;
    sscanf(pstr + 1, "%[^\n]", userid);

    return 1;
}

int get_user_name(SAI cliaddr, char *username)
{
    char *cliip;
    char *pstr;
    char buf[1024];
    char key[128];

    if (!g_cert_enable)
        return 1;

    if (username == NULL)
        return -1;

    cliip = inet_ntoa(cliaddr.sin_addr);

    if (!read_cert(buf, sizeof(buf)))
        return -1;

    if ((pstr = strstr(buf, cliip)) == NULL)
        return -1;
    sscanf(pstr, "%[^\n]", key);

    if ((pstr = strchr(key, '_')) == NULL)
        return -1;
    sscanf(pstr + 1, "%[^_]", username);

    return 1;
}

/*
 *  @ for DB33 control protocol.
 *  @ for H3C and other company.
 *  @ find client ip and port.
 */
int find_sip_addr(char **ut_buf, char *ip, char *port)
{
    char *pret;
    char  addr[32];

    if (ip == NULL || port == NULL)
        return -1;

    if ((pret = strstr(*ut_buf, "To: <sip:")) == NULL)
        return -2;

    pret = strstr(pret, "@");
    sscanf(pret + 1, "%[^>]", addr);

    if (strstr(addr, ":") == NULL) {
        if ((pret = strstr(*ut_buf, "From: <sip:")) == NULL)
            return -3;

        memset(&addr, 0x00, 32);
        pret = strstr(pret, "@");
        sscanf(pret + 1, "%[^>]", addr);
    }

    sscanf(addr, "%[^:]", ip);
    sscanf(addr + strlen(ip) + 1, "%[0-9]", port);

    return 1;
}

void
_wlog(const char *name, char *str)
{
    FILE *plog = NULL;
	time_t tnow = time(0);
    struct tm ltm;
    localtime_r(&tnow, &ltm);
    char stime[128] = {0};

    if ((name == NULL) || (str == NULL))
        return;

	sprintf(stime, "<y:%d m:%d d:%d   h:%d m:%d> ", ltm.tm_year + 1900, ltm.tm_mon + 1, ltm.tm_mday, ltm.tm_hour, ltm.tm_min);
    if ((plog = fopen(name, "a+")) == NULL)
        return;
    fwrite(stime, strlen(stime), 1, plog);
    puts(str);
    fputs(str, plog);
    fputs("\n", plog);
    fclose(plog);
}

void
_wlog2(const char *name, char *fmt, ...)
{
	va_list al;
	va_start(al, fmt);

	FILE *plog = NULL;
	time_t tnow = time(0); struct tm ltm;
	localtime_r(&tnow, &ltm);

	if ((name == NULL) || (fmt == NULL))
		return;
	if ((plog = fopen(name, "a+")) == NULL)
		return;

	fprintf(plog, "<y:%d m:%d d:%d   h:%d m:%d> ", ltm.tm_year + 1900, ltm.tm_mon + 1, ltm.tm_mday, ltm.tm_hour, ltm.tm_min);
	vfprintf(plog, fmt, al);
	fputs("", plog);

	fprintf(stdout, "<y:%d m:%d d:%d   h:%d m:%d> ", ltm.tm_year + 1900, ltm.tm_mon + 1, ltm.tm_mday, ltm.tm_hour, ltm.tm_min);
	vfprintf(stdout, fmt, al);
	fputs("", stdout);

	fclose(plog);

	va_end(al);
}

u32 get_inet_ip_from_socket(int sockfd)
{
    struct sockaddr_in saddr;
    socklen_t len;
    if (getsockname(sockfd, (struct sockaddr*)&saddr, &len) < 0)
        return -1;
    return saddr.sin_addr.s_addr;
}

u16 get_inet_port_from_socket(int sockfd)
{
    struct sockaddr_in saddr;
    socklen_t len = sizeof(saddr);
    if (getsockname(sockfd, (struct sockaddr*)&saddr, &len) < 0)
        return -1;
    return saddr.sin_port;
}

char*
loop_line_from_buf(char *cursor, char *store, int storesz)
{
    if ((cursor == NULL) || (store == NULL) || (storesz <= 0))
        return NULL;
    if (cursor[0] == '\0')
    {
        store[0] = '\0';
        return NULL;
    }

    char *ptr = strstr(cursor, "\n");
    int size = 0;
    if (ptr != NULL)
    {
		size = ptr - cursor;
		if (*(ptr - 1) == '\r')
			size -= 1;
			
        if (size > storesz - 1)
		{
			logdbg_out("loop_line_from_buf: store size is not large enough!");
            return NULL;
		}
        memcpy(store, cursor, size);
		store[size] = '\0';
        ptr += 1;
    }
    else
    {
        size = strlen(cursor);
        if (size > storesz - 1)
		{
			logdbg_out("loop_line_from_buf: store size is not large enough!");
            return NULL;
		}
        //strcpy(store, cursor);
		memcpy(store, cursor, size);
		store[size] = '\0';
    }

    return ptr;
}

const char *set_app_dir(const char *app_dir)
{
    return g_p_app_dir = app_dir;
}

