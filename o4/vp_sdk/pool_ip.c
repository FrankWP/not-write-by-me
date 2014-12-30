#include "pool_ip.h"

static ipp_list g_ipplist;

ip_pool * ippool_add(u32 lip, u32 dip)
{
    ip_pool *pn;

    if ((pn = (ip_pool *)malloc(sizeof(ip_pool))) == NULL)
        return pn;

    pn->lip = lip;
    pn->dip = dip;
    pn->flag = N_USE;
    memset(&(pn->vis_addr), 0x00, sizeof(SAI));

    __ipplist_add(&g_ipplist, pn);

    return pn;
}

void ippool_del_all()
{
    ip_pool          *pn;
    struct list_head *pos, *qn;

    list_for_each_safe(pos, qn, &g_ipplist.ippool.list) {
        pn = list_entry(pos, ip_pool, list);
        __ipplist_free(&g_ipplist, pn, pos);
    }
}

ip_pool * ippool_search_by_desaddr(SAI desaddr)
{
    ip_pool          *pn;
    struct list_head *pos;

    list_for_each(pos, &g_ipplist.ippool.list) {
        pn = list_entry(pos, ip_pool, list);
        if (!memcmp(&pn->vis_addr, &desaddr, sizeof(SAI)))
            return pn;
    }
    return NULL;
}

ip_pool * ippool_search_lip_pairs(u32 lip)
{   
    ip_pool          *pn;
    struct list_head *pos;

    list_for_each(pos, &g_ipplist.ippool.list) {
        pn = list_entry(pos, ip_pool, list);
        if (pn->lip == lip)
            return pn;
    }
    return NULL;
}

ip_pool * ippool_search_dip_pairs(u32 dip)
{   
    ip_pool          *pn;
    struct list_head *pos;


    list_for_each(pos, &g_ipplist.ippool.list) {
        pn = list_entry(pos, ip_pool, list);

        char dddip[32] = {0};
        memset(dddip, 0x00, sizeof(dddip));
        inet_ultoa(dip, dddip);
        printf("*** client dip: [%s] \n", dddip);

        char ddip[32] = {0};
        memset(ddip, 0x00, sizeof(ddip));
        inet_ultoa(pn->dip, ddip);
        printf("*** ip pool dest: pn dip[%s] \n", ddip);

        if (pn->dip == dip)
            return pn;
    }
    return NULL;
}


ip_pool * ippool_search_idle_addr(SAI desaddr)
{
    ip_pool          *pn;
    struct list_head *pos;

    list_for_each(pos, &g_ipplist.ippool.list) {
        pn = list_entry(pos, ip_pool, list);
        if (pn->flag == N_USE) {
            pn->flag = Y_USE;
            memcpy(&pn->vis_addr, &desaddr, sizeof(SAI));
            return pn;
        }
    }
    return NULL;
}

void ippool_rset_flag(SAI desaddr)
{
    ip_pool          *pn;
    struct list_head *pos;

    list_for_each(pos, &g_ipplist.ippool.list) {
        pn = list_entry(pos, ip_pool, list);
        if (!memcmp(&pn->vis_addr, &desaddr, sizeof(SAI))) {
            pn->flag = N_USE;
            memset(&pn->vis_addr, 0x00, sizeof(pn->vis_addr));
            return ;
        }
    }
    puts("ippool rset flag: not found!");
}

void ipplist_print()
{
    char             sl[32];
    char             sd[32];
    ip_pool          *pn;
    struct list_head *pos;

    list_for_each(pos, &g_ipplist.ippool.list) {
        pn = list_entry(pos, ip_pool, list);
        printf("flag = %d srcip = %s desip = %s\n",
                pn->flag, inet_ultoa(pn->lip, sl), inet_ultoa(pn->dip, sd));
    }
}

int load_ip_pool()
{
    u32     lip;
    u32     dip;
    char    iparray[2][64];
    FILE  * fp = NULL;
    char  * line = NULL;
    size_t  len = 0;
    ssize_t read;

    INIT_IPPOOL_LIST(&g_ipplist);

    if ((fp = fopen(FILE_PATH, "r")) == NULL)
        return -1;

    while ((read = getline(&line, &len, fp)) != -1) {
        if (strstr(line, "#") != NULL || line == NULL)
            continue ;
        getsubstring(line, iparray, ' ');

        lip = inet_atoul(iparray[0]);
        dip = inet_atoul(iparray[1]);

        ippool_add(lip, dip);
    }
    if (line)
        free(line);
    return 1;
}

char *pre_deal_with_line_pool_ip(char *line)
{
    char *ptr = NULL;

	if (line == NULL)
		return NULL;

    if ((ptr = strstr(line, "\n")) != NULL)
    {
        if (ptr - line > 1)
        {
            if (*(ptr - 1) == '\r')
                *(ptr - 1) = '\0';
        }
        *ptr = '\0';
    }
	if ((ptr = strstr(line, "\r")) != NULL)
	{
		*ptr = '\0';
	}

	if ((ptr = strstr(line, "#")) != NULL)
		*ptr = '\0'; 

//    trim(line);

    if (line[0] == '\0')
         return NULL;
        
    return line;
}

char*
line_from_buf2(char *cursor, char *store, int storesz)
{
    if ((cursor == NULL) || (store == NULL) || (storesz <= 0))
        return NULL;
    if (*cursor == '\0')
    {
        store[0] = '\0';
        return NULL;
    }

    char *ptr = strstr(cursor, "\n");
    int size = 0;
    if (ptr != NULL)
    {
        if (ptr - cursor > storesz - 1)
            return NULL;
        memcpy(store, cursor, ptr - cursor);
        ptr += 1;
        if (*ptr == '\0')
            return NULL;
    }
    else
    {
        size = strlen(cursor);
        if (size > storesz - 1)
            return NULL;
        strcpy(store, cursor);
//        ptr = store + size + 1;
    }

    return ptr;
}

int load_ip_pool2(const char *name)
{
	//int ret = -1;
    FILE *fp = NULL;

    if (name == NULL)
        return -1;

    if ((fp = fopen(FILE_PATH, "r")) == NULL)
        return -1;

    char *pBuf = NULL;
	struct stat fs;
	size_t filesz = 0;
	fstat(fp->_fileno, &fs);
	filesz = fs.st_size;
	if (filesz == 0)
    {
        fclose(fp);
		return -1;
    }
	pBuf = (char*)malloc(filesz);
	if (pBuf == NULL)
    {
        fclose(fp);
		return -1;
    }
	long nread = fread(pBuf, filesz, 1, fp);
	if (nread != 1)
	{
        fclose(fp);
		free(pBuf);
		return -1;
	}
    fclose(fp);

    char flg_beg[128] = {0};
    char flg_end[128] = {0};
    char *ptr_beg = NULL;
    char *ptr_end = NULL;

    sprintf(flg_beg, "[%s]", name);
    sprintf(flg_end, "[/%s]", name);
    if ( (ptr_beg = strstr(pBuf, flg_beg)) == NULL)
    {
        free(pBuf);
        return -1;
    }
    if ( (ptr_end = strstr(pBuf, flg_end)) == NULL)
    {
        free(pBuf);
        return -1;
    }
    if (ptr_end < ptr_beg)
    {
        free(pBuf);
        return -1;
    }
    ptr_beg += strlen(flg_beg);

    char *pNew = NULL;
    oss_malloc(&pNew, ptr_end - ptr_beg + 1);
    memcpy(pNew, ptr_beg, ptr_end - ptr_beg);
    oss_free(&pBuf);
    pBuf = pNew;
    
    u32     lip;
    u32     dip;
    char    iparray[2][64];
    char    read_line[128] = {0};
    char    *pFlg = NULL;
    char    *line_flg = NULL;
	//char *ptr_tmp = NULL;

    INIT_IPPOOL_LIST(&g_ipplist);
    pFlg = pBuf;
    while ((pFlg = line_from_buf2(pFlg, read_line, sizeof(read_line))) != NULL)
    {
        line_flg = pre_deal_with_line_pool_ip(read_line);
        if (line_flg == NULL)
            continue;
		//t_disbuf((u_char*)read_line, 128);
        getsubstring(read_line, iparray, ' ');
		//t_disbuf((u_char*)iparray[0], 64);
        printf("lip:%s\n", iparray[0]);
        printf("dip:%s\n", iparray[1]);

        lip = inet_atoul(iparray[0]);
        dip = inet_atoul(iparray[1]);

        ippool_add(lip, dip);
        memset(read_line, 0, sizeof(read_line));
    }
    return 1;
}

void free_ip_pool()
{
    DESTROY_IPPOOL_LIST(&g_ipplist);
}
