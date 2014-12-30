//#include "vp_sdk/sysheader.h"
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>
#include <dlfcn.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>

typedef enum {
    TRUE = 1,
    true = 1,
    FALSE = 0,
    false = 0
} BOOL, bool;

#define oss_malloc(p, size) __oss_malloc((void**)(p), size)
#define oss_free(ptr)   __oss_free((void**)(ptr))

typedef uint64_t	u64;
typedef uint32_t	u32;
typedef uint16_t	u16;
typedef uint8_t		u8;
typedef unsigned char u_char;
typedef long int      l_int;
typedef unsigned long int ul_int;

typedef struct __find_pos
{
    char *pos;
    int  len;
    struct __find_pos *next;
    struct __find_pos *prev;
}find_pos;

typedef struct __find_mem
{
    find_pos *fnd_pos;
    find_pos *fnd_pos_tail;
    find_pos *loop_cur;	// for loop getting position use.
    int nfind; // how many position have been find.
}find_mem;


void init_find(find_mem *fmem);
void clr_find(find_mem *fmem);
void add_find(find_mem *fmem, char *pfind);
char *loop_find(find_mem *fmem);
void reset_loop_find(find_mem *fmem, bool head);
char *loop_find_back(find_mem *fmem);


int __oss_malloc(void **p, int size)
{
    if ((*p = (void *)malloc(size)) == NULL) {
        syslog(LOG_INFO, "oss_malloc() failed");
        return -1;
    }
    memset(*p, 0x00, size);
    return 0;
}

void __oss_free(void **p)
{
    if (*p) {
        free(*p);
        *p = NULL;
    }
}

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


int array_replace(char *array, int sz_array, int *sz_valid,
        char *pos_b, char *pos_e, int times, char *src, int nsrc, char *dst, int ndst)
{
    find_mem fmem;
    char *pfind = NULL;
    int new_valid_sz = 0;
    char *pos = NULL;
    char *pos_last = NULL;
    //char *ptmp = NULL;
    char *ptail = NULL;
    int  ntimes = 0;
    int nNextLen = 0;
    char *pcp_dst = NULL;
    char *pcp_src = NULL;

    if (array == NULL || sz_valid == NULL)
    {
        //logdbg_out("Invalied array pointer or size pointer");
        return -1;
    }
    if (*sz_valid > sz_array)
    {
        //logdbg_fmt("Array size (%d) is less than valid data size (%d)!", sz_array, *sz_valid);
        return -1;
    }
    ptail = array + *sz_valid;

    if (pos_b == NULL)
        pos_b = array;
    if (pos_e == NULL)
        pos_e = ptail;
    if (pos_e < pos_b)
    {
        //logdbg_out("End pos of replace range is ahead of begin pos of replace range!");
        return -1;
    }
    if ( (pos_b - array > *sz_valid) || ((pos_b - array) < 0) )
    {
        //logdbg_out("Invalid begin pos!");
        return -1;
    }
    if ( (pos_e - array > *sz_valid) || ((pos_e - array) < 0) )
    {
        //logdbg_out("Invalid end pos!");
        return -1;
    }

    // search src
    init_find(&fmem);
    pos = pos_b;
    while (times != 0)
    {
        pfind = pos = (char*)memmem(pos, ptail - pos, src, nsrc);
        if (pfind != NULL)
        {
            if (pfind > pos_e)
                break;
            add_find(&fmem, pfind);
        }
        pos += nsrc;
        if ( (pos >= pos_e) || ((ptail - pos) < nsrc) )
            break;
        if (times > 0)
            --times;
    }
    if (fmem.nfind == 0)
        return 0;

    // replace src to dst
    pos = NULL;
    new_valid_sz = *sz_valid + (ndst - nsrc) * fmem.nfind;
    if (new_valid_sz > sz_array)
    {
        //logdbg_fmt("Array size %d is less than that after replace %d!", sz_array, new_valid_sz);
        return -1;
    }

    *sz_valid = new_valid_sz;

    if (nsrc == ndst)
    {
        while ( (pos = loop_find(&fmem)) != NULL)
            memcpy(pos, dst, ndst);
    }
    else if (nsrc > ndst)
    {
        reset_loop_find(&fmem, true);
        pos_last = loop_find(&fmem);
        pcp_dst = pos_last;

        do
        {
            pos = loop_find(&fmem);
            if (pos == NULL)
                pos = ptail;
            nNextLen = pos - (pos_last + nsrc);
            memcpy(pcp_dst, dst, ndst);
            pcp_dst += ndst;
            pcp_src = pos_last + nsrc;
            memmove(pcp_dst, pcp_src, nNextLen);
            pcp_dst += nNextLen;

            ++ntimes;
            pos_last = pos;
        } while (pos_last != ptail);
    }
    else // if (nsrc < ndst)
    {
        reset_loop_find(&fmem, false);
        //pos_last = loop_find_back(&fmem);
        pos_last = array + sz_array;
        ntimes = fmem.nfind;
        do
        {
            pos = loop_find_back(&fmem);
            if (pos == NULL)
                break;

            pcp_src = pos + nsrc;
            pcp_dst = pos + nsrc + ntimes * (ndst - nsrc);
            nNextLen = pos_last - (pos + nsrc);
            memmove(pcp_dst, pcp_src, nNextLen); 
            pcp_dst -= ndst;
            memcpy(pcp_dst, dst, ndst);

            pos_last = pos;
            --ntimes;
        } while (pos_last != array);
    }

    clr_find(&fmem);

    return fmem.nfind;
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

int main()
{
	char *p = (char*)malloc(32);
	memcpy(p, "111133" , 6);
	int len = strlen(p);
	char *src = "1111";
	char *dst = "22222";
	memreplace_pos(NULL, NULL, &p, &len, -1, src, strlen(src), dst, strlen(dst));
	printf("%s\n", p);
}
