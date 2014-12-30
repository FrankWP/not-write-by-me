#include "common.h"
#include "memreplace.h"

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
        logdbg_out("Invalied array pointer or size pointer");
        return -1;
    }
    if (*sz_valid > sz_array)
    {
        logdbg_fmt("Array size (%d) is less than valid data size (%d)!", sz_array, *sz_valid);
        return -1;
    }
    ptail = array + *sz_valid;

    if (pos_b == NULL)
        pos_b = array;
    if (pos_e == NULL)
        pos_e = ptail;
    if (pos_e < pos_b)
    {
        logdbg_out("End pos of replace range is ahead of begin pos of replace range!");
        return -1;
    }
    if ( (pos_b - array > *sz_valid) || ((pos_b - array) < 0) )
    {
        logdbg_out("Invalid begin pos!");
        return -1;
    }
    if ( (pos_e - array > *sz_valid) || ((pos_e - array) < 0) )
    {
        logdbg_out("Invalid end pos!");
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
        logdbg_fmt("Array size %d is less than that after replace %d!", sz_array, new_valid_sz);
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

