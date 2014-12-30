#include "visit_list.h"

clivlist * vlist_add(vlist *pvlist, u32 cliip, u16 cliport)
{
    clivlist *pcvn;

    if ((pcvn = (clivlist *)malloc(sizeof(clivlist))) == NULL)
        return pcvn;

    pcvn->cliip = cliip;
    pcvn->cliport = cliport;

    __vlist_add(pvlist, pcvn);

    return pcvn;
}

void vlist_del(vlist *pvlist, u32 cliip, u16 cliport)
{
    clivlist         *pn;
    struct list_head *pos, *qn;

    list_for_each_safe(pos, qn, &pvlist->cvlist.list) {
        pn = list_entry(pos, clivlist, list);
        if (pn->cliip == cliip && pn->cliport == cliport) {
            __vlist_free(pvlist, pn, pos);
            return ;
        }
    }
}

void vlist_del_by_cip(vlist *pvlist, u32 cliip)
{
    clivlist         *pn;
    struct list_head *pos, *qn;

    list_for_each_safe(pos, qn, &pvlist->cvlist.list) {
        pn = list_entry(pos, clivlist, list);
        if (pn->cliip == cliip) {
            __vlist_free(pvlist, pn, pos);
            return ;
        }
    }
}

void vlist_del_all(vlist *pvlist)
{
    clivlist         *pn = NULL;
    struct list_head *pos = NULL;
    struct list_head *qn = NULL;

    list_for_each_safe(pos, qn, &pvlist->cvlist.list) {
        pn = list_entry(pos, clivlist, list);
        __vlist_free(pvlist, pn, pos);
    }
}

clivlist * vlist_search(vlist *pvlist, u32 cliip, u16 cliport)
{
    clivlist         *pn;
    struct list_head *pos;

    list_for_each(pos, &pvlist->cvlist.list) {
        pn = list_entry(pos, clivlist, list);
        if ((pn->cliip == cliip) &&
                (pn->cliport == cliport))
            return pn;
    }
    return NULL;
}

clivlist * vlist_search_by_cip(vlist *pvlist, u32 cliip)
{
    clivlist         *pn;
    struct list_head *pos;

    list_for_each(pos, &pvlist->cvlist.list) {
        pn = list_entry(pos, clivlist, list);
        if (pn->cliip == cliip)
            return pn;
    }
    return NULL;
}

void vlist_print(vlist *pvlist)
{
    clivlist         *pn;
    struct list_head *pos;

    list_for_each(pos, &pvlist->cvlist.list) {
        pn = list_entry(pos, clivlist, list);
        printf("ip=%d port=%d\n", pn->cliip, pn->cliport);;
    }
}

clivlist * create_tuvs_smem(const char * psmid)
{
    int       fd, oflags;
    clivlist *pcvlist;

    oflags = O_RDWR | O_CREAT | O_EXCL;
    fd = shm_open(psmid, oflags, FILE_MODE);
    if (fd == -1) {
        if (errno == EEXIST)
            fd = shm_open(psmid, O_RDWR, FILE_MODE);
        else {
            syslog(LOG_INFO, "create client visit share mem failed.");
            return NULL;
        }
    }
    pcvlist = (clivlist*)mmap(NULL, sizeof(clivlist),
                   PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    ftruncate(fd, sizeof(clivlist));
    close(fd);

    return pcvlist;
}

