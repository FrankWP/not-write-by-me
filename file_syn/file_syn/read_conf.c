#include "read_conf.h"

struct sock_conf __sc;

void free_item(conf_item **item)
{
	conf_item *item_tmp = NULL;
	if ((item == NULL) || (*item == NULL))
		return;

	item_tmp = *item;
	while (item_tmp != NULL)
	{
		*item = item_tmp;
		item_tmp = item_tmp->item_next;

		if ((*item)->item_name != NULL)
			free((*item)->item_name);
		if ((*item)->item_value != NULL)
			free((*item)->item_value);
		free(*item);
	}

	*item = NULL;
}

query_conf *find_label(query_conf *p_query_conf, char *label_name)
{
	query_conf *que = NULL;

	if ((p_query_conf == NULL) || (label_name == NULL))
		return NULL;

	for (que = p_query_conf; que != NULL; que = que->label_next)
	{
		if (strcmp(que->label_name, label_name) == 0)
			break;
	}

	return que;
}

char *get_value_from_label(query_conf *que, char *item_name)
{
	conf_item *item = NULL;
	char *res = NULL;
	if ((que == NULL) || (item_name == NULL))
		return NULL;

	item = que->label_item;
	while (item != NULL)
	{
		if (strcmp(item->item_name, item_name) == 0)
		{
			res = item->item_value;
			break;
		}
		item = item->item_next;
	}
	return res;
}

char* trim(char *str)
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

char * inet_ultoa(unsigned int u, char * s)
{
    static char ss[20];

    if (s == NULL)
        s = ss;
    sprintf(s, "%d.%d.%d.%d",
            (unsigned int)(u>>24)&0xff, (unsigned int)(u>>16)&0xff,
            (unsigned int)(u>>8)&0xff, (unsigned int)u&0xff);
    return s;
}

unsigned int inet_atoul(const char * s)
{
    int i;
    int u[4];
    unsigned int rv;

    if(sscanf(s, "%d.%d.%d.%d", &u[0], &u[1], &u[2], &u[3]) == 4) {
        for (i = 0, rv = 0; i < 4; i++) {
            rv <<= 8;
            rv |= u[i] & 0xff;
        }
        return rv;
    } else
        return 0xffffffff;
}

char *pre_deal_with_line(char *line)
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

	if ((ptr = strstr(line, "#")) != NULL)
		*ptr = '\0'; 

    trim(line);

    if (line[0] == '\0')
         return NULL;
        
    return line;
}




static query_conf *deal_with_label_line(char *read_line, query_conf **p_conf_head, query_conf **p_conf_tail)
{
    char name[64] = {0};
    query_conf *p_conf_que = NULL;

    if (strncmp(read_line, "[", 1) == 0)
    {
        if (strncmp(read_line, "[/", 2) == 0)
            return NULL;

        sscanf(read_line+1, "%[^]]", name);
        if (name[0] == '\0')
            return NULL;

        p_conf_que = (query_conf *)malloc(sizeof(query_conf));
        p_conf_que->label_name = strdup(name);
        p_conf_que->label_item = NULL;
        p_conf_que->label_next = NULL;

        if ((*p_conf_head) == NULL)
        {
            (*p_conf_head) = p_conf_que;
        }
        else
        {
            (*p_conf_tail)->label_next = p_conf_que;
        }
        (*p_conf_tail) = p_conf_que;

    }

    return *p_conf_tail;
}

/*
 * parse line of label items such as 'name = value'
 */
static conf_item *deal_with_item_line(char *read_line, query_conf **p_conf_que, conf_item **p_item_tail)
{
    char name[64] = {0};
    char value[512] = {0};
    char *p_equal_sign = NULL;

	if ((read_line == NULL) || (p_conf_que == NULL) || (*p_conf_que == NULL) || (p_item_tail == NULL))
		return NULL;

    if ((p_equal_sign = strchr(read_line, '=')) != NULL)
    {
        name[0] = '\0';
        value[0] = '\0';

        if ((*p_conf_que)->label_name[0] == '\0')
            return NULL;

        if ( p_equal_sign[1] == '\0')
        {
            sscanf(read_line, "%[^=]", name);
            sprintf(value, "%s", "");
        }
        else
        {
            sscanf(read_line, "%[^=]", name);
            p_equal_sign += 1;
            sscanf(p_equal_sign, "%[^ ]", value);
        }

        conf_item *p_item_node = (conf_item *)malloc(sizeof(conf_item));
        p_item_node->item_name = strdup(name);
        p_item_node->item_value = strdup(value);

        if ((*p_conf_que)->label_item == NULL)
            (*p_conf_que)->label_item = p_item_node;
        else
            (*p_item_tail)->item_next = p_item_node;
        *p_item_tail = p_item_node;
    }

    return *p_item_tail;
}




char* line_from_buf(char *cursor, char *store, int storesz)
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
        memcpy(store, cursor, ptr - cursor + 1);
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



query_conf * load_configuration(const char *filepath)
{
    FILE *fp = NULL;

    char read_line[2048] = {0};
    //int  line_sz = 2048;
    char *line_flg = NULL;

    query_conf *p_conf_head = NULL;
    query_conf *p_conf_tail = NULL;
    conf_item *p_item_tail = NULL;

    if (filepath == NULL)
        return NULL;

    if ((fp = fopen(filepath, "r")) == NULL)
    {
        return NULL;
    }

    char *pBuf = NULL;
	struct stat fs;
	size_t filesz = 0;
	fstat(fp->_fileno, &fs);
	filesz = fs.st_size;
	if (filesz == 0)
    {
        fclose(fp);
		return NULL;
    }
	pBuf = (char*)malloc(filesz);
	if (pBuf == NULL)
    {
        fclose(fp);
		return NULL;
    }
	long nread = fread(pBuf, filesz, 1, fp);
	if (nread != 1)
	{
        fclose(fp);
		free(pBuf);
		return NULL;
	}

    //bool bIsGeneral = false;
    char *pFlg = strstr(pBuf, "[");
    if (pFlg == NULL)
    {
        //bIsGeneral = true;
    }
    else 
        pFlg = strstr(pFlg, "]");
    if (pFlg == NULL)
    {
        //bIsGeneral = true;
        p_conf_head = (query_conf *)malloc(sizeof(query_conf));
        char *general_name = (char*)malloc(32);
        strcpy(general_name, "default");
        p_conf_head->label_name = general_name;
        p_conf_head->label_item = NULL;
        p_conf_head->label_next = NULL;
        p_conf_tail = p_conf_head;
    }

    //while (feof(fp) == 0)
    pFlg = pBuf;
    while ((pFlg = line_from_buf(pFlg, read_line, sizeof(read_line))) != NULL)
    {
        //memset(read_line, 0, sizeof(read_line));
        //fgets(read_line, line_sz, fp);

        line_flg = pre_deal_with_line(read_line);
        if (line_flg == NULL)
            continue;
        puts(read_line);

        if (strncmp(read_line, "[", 1) == 0)
        {
            if (deal_with_label_line(read_line, &p_conf_head, &p_conf_tail) == NULL)
                continue;
        }

        if (strstr(read_line, "=") != NULL)
        {
            if (deal_with_item_line(read_line, &p_conf_tail, &p_item_tail) == NULL)
                continue; 
        }

        memset(read_line, 0, sizeof(read_line));
    }

    if (p_item_tail != NULL)
		p_item_tail->item_next = NULL;
    if (p_conf_tail != NULL)
		p_conf_tail->label_next = NULL;

    //fclose(fp);
    return p_conf_head;
}

void free_configuration(query_conf **pque)
{
	query_conf *que = NULL;

	if ((pque == NULL) || (*pque == NULL))
		return;
	
	que = *pque;
	while (que != NULL)
	{
		*pque = que;
		que = que->label_next;

		free_item(&((*pque)->label_item));
	}
	*pque = NULL;
}

/*
int main()
{
    char *val = NULL;
	char *path = "sock.conf";
    struct	sockaddr_in s_addr;

	query_conf *general = NULL;
	query_conf *conf = NULL;

	if ((conf = load_configuration(path)) == NULL)
	{
        return -1;
	}

	if ((general = find_label(conf, (char*)"socket")) == NULL)
	{
		free_configuration(&conf);
		return -1;
	}
	
	if ((val = get_value_from_label(general, (char*)"synconf_ip")) != NULL)
        __sc.s_ip = inet_atoul(val);
	printf("ip:%s\n", val);

	if ((val = get_value_from_label(general, (char*)"synconf_port")) != NULL)
        __sc.s_port = inet_atoul(val);
	printf("port:%s\n", val);

	s_addr.sin_family = AF_INET;
    s_addr.sin_port = htons(__sc.s_port);
    s_addr.sin_addr.s_addr = htonl(__sc.s_ip);

	

	free_configuration(&conf);

	return 0;
}
*/
