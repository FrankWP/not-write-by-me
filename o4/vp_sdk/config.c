#include "common.h"

static query_conf *deal_with_label_line(char *read_line, query_conf **p_conf_head, query_conf **p_conf_tail);
static conf_item *deal_with_item_line(char *read_line, query_conf **p_conf_que, conf_item **p_item_tail);

char m_conf_key[][SZ_CFGVAL] = {
    "local_auth_ip",
    "local_auth_port",
    "dest_auth_ip",
    "dest_auth_port",
    "vap_peer_addr",
    "session_timeout",
    "local_video_ip",
    "local_video_port",
    "dest_video_ip",
    "dest_video_port",
};

struct general_config_t g_general_config = { is_loaded: 0, };
frame_modify_paras g_frmp = {false,0,0};

/*
 * func 
 *	1.cut signs '\r\n' from lines 
 *	2.filter empty lines 
 *	3.cut space,table signs
 */
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

/*
 * parse line of labels such as '[label name]'
 */
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

char*
line_from_buf(char *cursor, char *store, int storesz)
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


/*
 * read config file and assign the value to a struct linker
 */
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
        logwar_fmt("打开文件 %s 失败!", filepath);
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
        strcpy(general_name, "general");
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
        //puts(read_line);

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

char *get_conf_value(char *label_name, char *item_name, query_conf *p_query_conf)
{
    query_conf *que = NULL;

    if ((p_query_conf == NULL) || (label_name == NULL) || (item_name == NULL))
        return NULL;

    que = p_query_conf;

    for (; que != NULL; que = que->label_next)
    {
        if (strncmp(que->label_name, label_name, strlen(label_name)) == 0)
        {
            for (; que->label_item != NULL; que->label_item = que->label_item->item_next)
            {
                if (strncmp(que->label_item->item_name, item_name, strlen(item_name)) == 0)
                    return que->label_item->item_value;
            }
        }
    }

    return NULL;
}

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

static char * remove_path_slash(char * s)
{
    size_t len;
    int i;
    if(!s)
        return NULL;
    len = strlen(s);
    for(i=len-1; i>=0 && s[i]=='/'; i--)
        s[i] = '\0';
    return s;
}

int __load_general_config()
{
    return __load_general_config_path(GENERAL_CONFIG_FILE);
}

int __load_general_config_path(const char *path)
{
    static char s_app_dir[100] = {0};
	int ret = -1;
    char * val = NULL;
	query_conf *conf = NULL;
	query_conf *general = NULL;
    char hostname[40] = {0};

	if ( __gg.is_loaded)
		return 0;

	if ((conf = load_configuration(path)) == NULL)
	{
        loginf_out("Loading platform configurations error.");
        return -1;
	}

	if ((general = find_label(conf, (char*)"general")) == NULL)
	{
		free_configuration(&conf);
		loginf_out("Formating of file error!");
		return -1;
	}

    memset(&__gg, 0x0, sizeof(__gg));
    ret = gethostname(hostname, sizeof(hostname));
    if (ret == 0) {
        __gg.host_side = HOST_SIDE_INNER;
        if(strstr(hostname, "inner")  ||
                strstr(hostname, "inside") ||
                strstr(hostname, "tms")    ||
                strstr(hostname, "TMS"))
        {
            __gg.host_side = HOST_SIDE_INNER;
        }
        else if(strstr(hostname, "outer")   ||
                strstr(hostname, "outside") ||
                strstr(hostname, "ums")     ||
                strstr(hostname, "UMS"))
        {
            __gg.host_side = HOST_SIDE_OUTER;
        }
    }

	if ((val = get_value_from_label(general, (char*)"inner_priv_addr")) != NULL)
        __gg.inner_priv_addr = inet_atoul(val);

    if ((val = get_value_from_label(general, (char*)"outer_priv_addr")) != NULL)
        __gg.outer_priv_addr = inet_atoul(val);

    if ((val = get_value_from_label(general, (char*)"inner_addr")) != NULL)
        __gg.inner_addr = inet_atoul(val);

    if ((val = get_value_from_label(general, (char*)"outer_addr")) != NULL)
        __gg.outer_addr = inet_atoul(val);

    if ((val = get_value_from_label(general, (char*)"ferry_port")) != NULL)
        __gg.ferry_port = (u16)atoi(val);

    if ((val = get_value_from_label(general, (char*)"sysmana_port")) != NULL)
        __gg.sysmana_port = (u16)atoi(val);

    if ((val = get_value_from_label(general, (char*)"app_dir")) != NULL)
	{
        strcpy(s_app_dir, remove_path_slash(val) );
        __gg.app_dir = s_app_dir;
    }
    __gg.sz_buffer = BUF_SIZE;
    if ((val = get_value_from_label(general, (char*)"size_buffer")) != NULL)
    {   
        __gg.sz_buffer = atoi(val);
    }   
    if (__gg.host_side == HOST_SIDE_INNER) {
        __gg.local_priv_addr = __gg.inner_priv_addr;
        __gg.peer_priv_addr = __gg.outer_priv_addr;
    } else if(__gg.host_side == HOST_SIDE_OUTER) {
        __gg.local_priv_addr = __gg.outer_priv_addr;
        __gg.peer_priv_addr = __gg.inner_priv_addr;
    }
    __gg.is_loaded = 1;
	free_configuration(&conf);
	
    return 0;
}

bool init_frame_paras()
{
    query_conf *que = NULL;

	if ((que = load_configuration(SYS_CONFIG_FILE)) != NULL)
	{
		g_frmp.frame_enable = (bool)atoi(get_conf_value((char*)"custom", (char*)"frame_start_flg", que));
		g_frmp.frame_modify_flg = atoi(get_conf_value((char*)"custom", (char*)"frame_modfy_flg", que));
		g_frmp.frame_modify_num = atoi(get_conf_value((char*)"custom", (char*)"frame_modfy_num", que));
		free_configuration(&que);
		return true;
	}

    return false;
}

int frame_run_count(int * count)
{
	if ((count == NULL) || ! g_frmp.frame_enable)
		return 0;

    if ((*count) % g_frmp.frame_modify_num == 0)
    {
        (*count) = 1;
        return 1;
    }
    else
    {
        (*count)++;
        return 0;
    }
}

