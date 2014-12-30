#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <regex.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include "filter_rules.h"

#define MYSQL_ERR_OUT(mysql) if(mysql_errno(mysql)) syslog(LOG_ERR, "过滤器错误(数据库错误):%s", mysql_error(mysql));

#define INF_OUT(info) syslog(LOG_INFO, "%s", info);
#define WAR_OUT(info) syslog(LOG_WARNING, "%s", info);
#define ERR_OUT(info) syslog(LOG_ERR, "%s", info);
#define	DBG_OUT(info) syslog(LOG_DEBUG, "%s", info);
#define SYS_INF(fmt, args...) syslog(LOG_INFO, fmt, args);
#define SYS_WAR(fmt, args...) syslog(LOG_WARNING, fmt, args);
#define SYS_ERR(fmt, args...) syslog(LOG_ERR, fmt, args);
#define	SYS_DBG(fmt, args...) syslog(LOG_DEBUG, args);

#define FR_ALLOC(fr_type)	\
    fr_type *pfr = (fr_type*)malloc(sizeof(fr_type));	\
if (pfr != 0)	\
{	\
    memset(pfr, 0, sizeof(fr_type));	\
}	\
return pfr;

#define FR_FREE(fr_type, fr)	\
    if (fr != 0) \
{	\
    fr_type *tmp = 0;	\
    fr_type *curr = *fr;	\
    while (curr != 0)	\
    {	\
        tmp = curr;	\
        curr = curr->next;	\
        free(tmp);	\
    }	\
    *fr = 0;	\
}

//static char *server_options[] = {"mysql_test", "--defaults-file=my.cnf"};
//int num_elements = sizeof(server_options) / sizeof(char*);
//static char *server_groups[] = {"libmysqld_server", "libmysqld_client"};

static const char QUERY_STR_FR_TIME[] = "SELECT time_rule_id, time_rule_start_time, time_rule_end_time, time_rule_mode, time_rule_status FROM vgap_time_rule"; 
static const char QUERY_STR_FR_SIP[] = "SELECT sip_rule_id, sip_rule_source_ip, sip_rule_source_mask, sip_rule_status FROM vgap_sourceip_rule";
static const char QUERY_STR_FR_DIP[] = "SELECT des_iprule_id, des_iprule_ip, des_iprule_mask, des_iprule_status FROM vgap_desip_rule";
static const char QUERY_STR_FR_ACCCTL[] = "SELECT access_id, access_user_name, access_source_ip, access_source_mask, access_des_ip, access_des_mask, access_sign, access_start_time, access_end_time, access_time_rule_mode FROM vgap_access_control";
static const char QUERY_STR_FR_STRING[] = "SELECT str_rule_id, str_rule_direction, str_rule_is_regular, str_differentiate, str_rule_expression FROM vgap_string_rule";
static const char QUERY_STR_FR_CTRLCMD[] = "SELECT pro_id, pro_cmd_name, pro_url, pro_status, pro_isbinary FROM vgap_protocol_control";

static char EMPTY_STR[1] = {0};
/////////////////////////////////////////////////////////////////
// functions declare

static fr_time *alloc_fr_time();
static fr_ip *alloc_fr_ip();
static fr_accctl *alloc_fr_accctl();
static fr_string *alloc_fr_string();
static fr_ctrlcmd *alloc_fr_ctrlcmd();
//static fr_proto *alloc_fr_proto();
static flt_rules *alloc_flt_rules();

static void free_fr_time(fr_time **frtime);
static void free_fr_ip(fr_ip **frip);
static void free_fr_accctl(fr_accctl **fraccctl);
static void free_fr_string(fr_string **frstring);
static void free_fr_ctrlcmd(fr_ctrlcmd **frctrlcmd);
//static void free_fr_proto(fr_proto **frproto);
static void free_flt_rules(flt_rules **fr);

static bool load_fr_time(FILTER *flt);
static bool load_fr_sip(FILTER *flt);
static bool load_fr_dip(FILTER *flt);
static bool load_fr_accctl(FILTER *flt);
static bool load_fr_string(FILTER *flt);
static bool load_fr_ctrlcmd(FILTER *flt);

static bool filter_time(fr_time *frtime, time_t t, int *rid);
static bool filter_ip(fr_ip *frip, int inet_ip, int inet_mask, int *rid);
static bool filter_accctl(fr_accctl *fraccctl, char *uname, int inet_sip, int inet_smask, int inet_dip, int inet_dmask, time_t t, int *rid);
static bool filter_string(fr_string *frstring, char *string, int len, int direct, int *rid);
static bool filter_ctrlcmd(fr_ctrlcmd *frctrlcmd, char *cmd, int len, int *rid);

static int a2i(char *ansi_num);
static char *strncpy_safe(char *dest, char *src, size_t n);
//static bool b_strncmp_sen(char *s1, char *s2, int n, bool sensitive);
static bool has_empty_record(MYSQL_ROW record, int num_idx, ...);
static MYSQL_RES* flt_get_results(FILTER *flt, const char* str, int len_str);
static bool regex_match(char *reg_exp, int reg_flag, char *string);
static int calc_inetid(int inetip, int inetmask);
//static bool match_char(char ch1, char ch2, bool sensitive);
//static bool is_in_range(int min, int max, int beg, int end, int pos);
static bool is_in_range(int min, int max, int beg, int end, int pos, bool inc_frontier);
static bool is_time_in_rule(time_t t, int t_beg, int t_end, int mode);
static bool parse_bcmd(bin_cmd **bcmd, bool is_bin, char *buf, int len);

// protocol type check
static bool fr_is_http(char *buf, int len);
static bool fr_is_ftp(char *proto, int len);
static bool fr_is_sip(char *proto, int len);
static bool fr_is_rtsp(char *proto, int len);
static bool fr_is_amplesky(char *proto, int len);
static enum __e_proto_type proto_type(char *proto, int len, char type[16]);

//////////////////////////////////////////////////////////
// functions that alloc and initialize structs

static fr_time		*alloc_fr_time()	{ FR_ALLOC(fr_time); }
static fr_ip		*alloc_fr_ip()		{ FR_ALLOC(fr_ip); }
static fr_accctl	*alloc_fr_accctl()	{ FR_ALLOC(fr_accctl); }
static fr_string	*alloc_fr_string()	{ FR_ALLOC(fr_string); }
static fr_ctrlcmd	*alloc_fr_ctrlcmd() { FR_ALLOC(fr_ctrlcmd); }
//static fr_proto		*alloc_fr_proto()	{ FR_ALLOC(fr_proto); }
static flt_rules	*alloc_flt_rules()	{ FR_ALLOC(flt_rules); }

//////////////////////////////////////////////////////////
// functions that free structs

static void free_fr_time(fr_time **frtime)			{ FR_FREE(fr_time, frtime); }
static void free_fr_ip(fr_ip **frip)				{ FR_FREE(fr_ip, frip); }
static void free_fr_accctl(fr_accctl **fraccctl)	{ FR_FREE(fr_accctl, fraccctl); }
static void free_fr_string(fr_string **frstring)	{ FR_FREE(fr_string, frstring); }
static void free_fr_ctrlcmd(fr_ctrlcmd **frctrlcmd)
{
	if (frctrlcmd == NULL)
		return;

	fr_ctrlcmd *tmp = NULL;
	bin_cmd	   *pCmd = NULL;
	bin_cmd	   *pTmpCmd = NULL;
	fr_ctrlcmd *curr = *frctrlcmd;
	while (curr != NULL)
	{
		tmp = curr;
		curr = curr->next;

		pCmd = tmp->bcmd;
		while (pCmd != NULL)
		{
			pTmpCmd = pCmd;
			pCmd = pCmd->next;
			if (pTmpCmd->cmd != NULL)
				free(pTmpCmd->cmd);
			free(pTmpCmd);
		}
		free(tmp);
	}

	*frctrlcmd = NULL;
}

static void
free_flt_rules(flt_rules **fr)
{
    if (fr == 0)
        return;

    flt_rules *tmp = 0;
    flt_rules *ptr_fr = *fr;
    while (ptr_fr != 0)
    {
        tmp = ptr_fr;
        ptr_fr = ptr_fr->next;

        free_fr_time( &(tmp->pfr_time) );
        free_fr_ip( &(tmp->pfr_sip) );
        free_fr_ip( &(tmp->pfr_dip) );
        free_fr_accctl( &(tmp->pfr_accctl) );
        free_fr_string( &(tmp->pfr_string) );
        free_fr_ctrlcmd( &(tmp->pfr_ctrlcmd) );

        free(tmp);
    }

    *fr = 0;
}

//////////////////////////////////////////////////////////
// load detail filter rules

static int
a2i(char *ansi_num)
{
    if (ansi_num == 0)
        return -1;

    return atoi(ansi_num);
}

static char*
strncpy_safe(char *dest, char *src, size_t n)
{
    if (dest != 0)
    {
        if (src != 0)
            strncpy(dest, src, n);
        else
            dest[0] = 0;
    }

    return dest;
}

static bool
has_empty_record(MYSQL_ROW record, int num_idx, ...)
{
    va_list al;

    va_start(al, num_idx);
    int val = 0;
    while (num_idx > 0)
    {
        val = va_arg(al, int);
        if (record[val] == 0)
            break;
        --num_idx;
    }
    va_end(al);

    return !(num_idx == 0);
}

static MYSQL_RES*
flt_get_results(FILTER *flt, const char* str, int len_str)
{
    char query[1024] = {0};
    int len = strlen(flt->fr->svrid) + len_str + (sizeof(" where service_id='' and flag = '1'") - 1);
    MYSQL_RES* res = 0;

    sprintf(query, "%s where service_id='%s' and flag = '1'", str, flt->fr->svrid); 
    if ( mysql_real_query(flt->ptr_mysql, query, len) == 0)
        res = mysql_store_result(flt->ptr_mysql);

    if ( res != NULL )
    {
        if ( mysql_num_rows(res) == 0 )
        {
            mysql_free_result(res);
            char table_name[32] = {0};
            char *pfrom = strstr((char*)str, (char*)"FROM");
            if (pfrom != 0)
                sscanf(pfrom + sizeof("FROM ")-1, "%s", table_name);
            SYS_INF("数据库表[%s]中，没有关于服务id[%s]的记录\n", table_name, flt->fr->svrid);
            return 0;
        }
    }
    return  res;
}

static bool
load_fr_time(FILTER *flt)
{
    MYSQL_RES* res = flt_get_results(flt, QUERY_STR_FR_TIME, sizeof(QUERY_STR_FR_TIME));
    if (res == 0)
    {
        MYSQL_ERR_OUT(flt->ptr_mysql);
        return false;
    }

    MYSQL_ROW record;
    fr_time *pfr_time = 0;
    while ( (record = mysql_fetch_row(res)) != 0) 
    {
        if ( has_empty_record(record, 5, 0,1,2,3,4))
        {
            WAR_OUT("从数据库加载时，[时间]记录有空值.");
            continue;
        }

        if (flt->fr->pfr_time != 0)
        {
            pfr_time->next = alloc_fr_time();
            pfr_time = pfr_time->next;
        }
        else
        {
            flt->fr->pfr_time = pfr_time = alloc_fr_time();
        }

        pfr_time->id = a2i(record[0]);
        pfr_time->t_beg = a2i(record[1]);
        pfr_time->t_end = a2i(record[2]);
        pfr_time->t_mode = a2i(record[3]);
        pfr_time->stat = a2i(record[4]);
    }
    mysql_free_result(res);
    return true;
}

static bool
load_fr_sip(FILTER* flt)
{
    MYSQL_RES* res = flt_get_results(flt, QUERY_STR_FR_SIP, sizeof(QUERY_STR_FR_SIP));
    if (res == 0)
    {
        MYSQL_ERR_OUT(flt->ptr_mysql);
        return false;
    }

    MYSQL_ROW record;
    fr_ip *pfr_sip = 0;

    while( (record = mysql_fetch_row(res)) != 0 )
    {
        if ( has_empty_record(record, 4, 0,1,2,3))
        {
            WAR_OUT("从数据库加载时，[源IP]记录有空值.");
            continue;
        }

        if ( flt->fr->pfr_sip != 0 )
        {
            pfr_sip->next = alloc_fr_ip();
            pfr_sip = pfr_sip->next;
        }
        else 
        {
            flt->fr->pfr_sip = pfr_sip = alloc_fr_ip();
        }

        pfr_sip->id = a2i(record[0]);
        pfr_sip->inet_ip = inet_addr(record[1]);
        pfr_sip->inet_mask = inet_addr(record[2]);
        pfr_sip->stat = a2i(record[3]);
    }

    mysql_free_result(res);

    return true;
}

static bool
load_fr_dip(FILTER* flt)
{
    MYSQL_RES* res = flt_get_results(flt, QUERY_STR_FR_DIP, sizeof(QUERY_STR_FR_DIP));
    if (res == 0)
    {
        MYSQL_ERR_OUT(flt->ptr_mysql);
        return false;
    }

    MYSQL_ROW record;
    fr_ip *pfr_dip = 0;

    while( (record = mysql_fetch_row(res)) != 0 )
    {
        if ( has_empty_record(record, 4, 0,1,2,3))
        {
            WAR_OUT("从数据库加载时，[目的IP]记录有空值.");
            continue;
        }

        if ( flt->fr->pfr_dip != 0 )
        {
            pfr_dip->next = alloc_fr_ip();
            pfr_dip = pfr_dip->next;
        }
        else 
        {
            flt->fr->pfr_dip = pfr_dip = alloc_fr_ip();
        }

        pfr_dip->id = a2i(record[0]);
        pfr_dip->inet_ip = inet_addr(record[1]);
        pfr_dip->inet_mask = inet_addr(record[2]);
        pfr_dip->stat = a2i(record[3]);
    }
    mysql_free_result(res);

    return true;

}

static bool
load_fr_accctl(FILTER* flt)
{
    MYSQL_RES* res = flt_get_results(flt, QUERY_STR_FR_ACCCTL, sizeof(QUERY_STR_FR_ACCCTL));
    if (res == 0)
    {
        MYSQL_ERR_OUT(flt->ptr_mysql);
        return false;
    }

    MYSQL_ROW record;
    fr_accctl *pfr_accctl = 0;
    while ( (record = mysql_fetch_row(res)) != 0)
    {
        if ( has_empty_record(record, 10, 0,1,2,3,4,5,6,7,8,9))
        {
            WAR_OUT("从数据库加载时，[访问控制]记录有空值.");
            continue;
        }

        if ( flt->fr->pfr_accctl != 0 )
        {
            pfr_accctl->next = alloc_fr_accctl();
            pfr_accctl = pfr_accctl->next;
        }
        else 
        {
            flt->fr->pfr_accctl = pfr_accctl = alloc_fr_accctl();
        }

        pfr_accctl->id = a2i(record[0]);
        strncpy_safe(pfr_accctl->uname, record[1], sizeof(pfr_accctl->uname));
        pfr_accctl->inet_sip = inet_addr(record[2]);
        pfr_accctl->inet_smask = inet_addr(record[3]);
        pfr_accctl->inet_dip = inet_addr(record[4]);
        pfr_accctl->inet_dmask = inet_addr(record[5]);

        pfr_accctl->stat = (bool)a2i(record[6]);
        pfr_accctl->t_beg = a2i(record[7]);
        pfr_accctl->t_end = a2i(record[8]);
        pfr_accctl->t_mode = a2i(record[9]);
    }
    mysql_free_result(res);

    return true;
}

static bool
load_fr_string(FILTER* flt)
{
    MYSQL_RES* res = flt_get_results(flt, QUERY_STR_FR_STRING, sizeof(QUERY_STR_FR_STRING));
    if (res == 0)
    {
        MYSQL_ERR_OUT(flt->ptr_mysql);
        return false;
    }

    MYSQL_ROW record;
    fr_string *pfr_string = 0;	

    while ( (record = mysql_fetch_row(res)) != 0 )
    {
        if ( has_empty_record(record, 5, 0,1,2,3,4))
        {
            WAR_OUT("从数据库加载时，[关键字]记录有空值.");
            continue;
        }

        if ( flt->fr->pfr_string != 0 )
        {
            pfr_string->next = alloc_fr_string();
            pfr_string = pfr_string->next;
        }
        else 
        {
            flt->fr->pfr_string = pfr_string = alloc_fr_string();
        }

        pfr_string->id = a2i(record[0]);
        pfr_string->direct = (a2i(record[1]) == 0) ? FILTER_DIR_C2S : FILTER_DIR_S2C;
        pfr_string->is_regular = (bool)a2i(record[2]);
        pfr_string->sensitive = a2i(record[3]);
        if (pfr_string->is_regular && !pfr_string->sensitive)
            pfr_string->reg_flag = REG_ICASE;
        strncpy_safe(pfr_string->expr, record[4], sizeof(pfr_string->expr)-1);
    }

    mysql_free_result(res);
    return true;
}

static bool 
parse_bcmd(bin_cmd **bcmd, bool is_bin, char *buf, int buf_len)
{
	u16	*pos = NULL;
	u16 *len = NULL;
	char *data = NULL;

	if (bcmd == NULL || *bcmd != NULL || buf == NULL || buf_len == 0)
		return false;

	*bcmd = (bin_cmd*)malloc(sizeof(bin_cmd));
	memset(*bcmd, 0, sizeof(bin_cmd));
	bin_cmd *pTmp = *bcmd;

	int i = 0;
	while (i < buf_len)
	{
		if ( ! is_bin)
		{
			pTmp->pos = -1;
			pTmp->len = buf_len;
			pTmp->cmd = (char*)malloc(buf_len + 1);
			memcpy(pTmp->cmd, buf, buf_len);
			pTmp->cmd[buf_len] = 0;
			break;
		}
		else
		{
			pos = (u16*)(buf + i);
			len = (u16*)(buf + sizeof(u16) + i);
			data = buf + sizeof(u16)*2 + i;
			i += *len + sizeof(u16)*2;
			if (i > buf_len)
			{
				WAR_OUT("加?二进制信令错误,数据异常");
				break;
			}
			pTmp->pos = *pos;
			pTmp->len = *len;
			pTmp->cmd = (char*)malloc(*len);
			memcpy(pTmp->cmd, data, *len);
			pTmp->next = NULL;
		}

		if (i < buf_len)
		{
			pTmp->next = (bin_cmd*)malloc(sizeof(bin_cmd));
			pTmp = pTmp->next;
			pTmp->next = NULL;
		}
	}

	return true;
}

static bool
load_fr_ctrlcmd(FILTER *flt)
{
    MYSQL_RES* res = flt_get_results(flt, QUERY_STR_FR_CTRLCMD, sizeof(QUERY_STR_FR_CTRLCMD));
    if (res == 0)
    {
        MYSQL_ERR_OUT(flt->ptr_mysql);
        return false;
    }

    MYSQL_ROW record;
    fr_ctrlcmd *pfr_ctrlcmd = 0;
	unsigned long *lengths = NULL;

    while ( (record = mysql_fetch_row(res)) != 0 )
    {
        if ( has_empty_record(record, 5, 0,1,2,3,4))
        {
            WAR_OUT("从数据库加载时，[控制信令]记录有空值.");
            continue;
        }

        if ( flt->fr->pfr_ctrlcmd != 0 )
        {
            pfr_ctrlcmd->next = alloc_fr_ctrlcmd();
            pfr_ctrlcmd = pfr_ctrlcmd->next;
        }
        else 
        {
            flt->fr->pfr_ctrlcmd = pfr_ctrlcmd = alloc_fr_ctrlcmd();
        }

		lengths = mysql_fetch_lengths(res);
		pfr_ctrlcmd->bcmd = NULL;
		parse_bcmd(&pfr_ctrlcmd->bcmd, (bool)a2i(record[4]), record[2], lengths[2]);
        pfr_ctrlcmd->id = a2i(record[0]);
		strncpy_safe(pfr_ctrlcmd->name, record[1], sizeof(pfr_ctrlcmd->name));
        pfr_ctrlcmd->stat = a2i(record[3]);
        pfr_ctrlcmd->sensitive = false;
    }

    mysql_free_result(res);
    return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////
// filter details

static bool
is_in_range(int min, int max, int beg, int end, int pos, bool inc_frontier)
{
    int large_num = max - min + 1;
    int base_val = beg;

    end = (end - base_val + large_num) % large_num;
    pos = (pos - base_val + large_num) % large_num;

	if (inc_frontier)
		++pos;

    return pos < end;
}

static int
calc_inetid(int inetip, int inetmask)
{
    return inetip & inetmask;
}

/*
static bool 
b_strncmp_sen(char *s1, char *s2, int n, bool sensitive)
{
    if (!sensitive)
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

    return strncmp(s1, s2, n) == 0;
}
*/

static bool
is_time_in_rule(time_t t, int t_beg, int t_end, int mode)
{
    struct tm gmtm;
    //	if (gmtime_r(&t, &gmtm) == 0)
    if (localtime_r(&t, &gmtm) == 0)
    {
        WAR_OUT("格式化时间失败.");
        return false;
    }

    bool is_in_rule = false;
    switch (mode)
    {
        case 0:
            is_in_rule = is_in_range(0, 24, t_beg, t_end, gmtm.tm_hour, false);
            break;
        case 1:
            is_in_rule = is_in_range(0, 6, t_beg, t_end + 1, gmtm.tm_wday, true);
            break;
    }

    return is_in_rule;
}

static bool
filter_time(fr_time *frtime, time_t t, int *rid/*rule id matched*/)
{
    if (frtime == 0)    // there is no rule, all can through.
        return true;

    if (rid != 0)
        *rid = -1;
    bool is_use_whitelist = (bool)frtime->stat;	// 0->blacklist; 1->whitelist
    bool is_in_rule = false;
    while (frtime)
    {
        if ( (is_in_rule = is_time_in_rule(t, frtime->t_beg, frtime->t_end, frtime->t_mode)) == true)
        {
            if (rid != 0)
                *rid = frtime->id;
            break;
        }
        frtime = frtime->next;
    }

    return !(is_in_rule ^ is_use_whitelist);
}

static bool
filter_ip(fr_ip *frip, int inet_ip, int inet_mask, int *rid)
{
    if (frip == 0)  // there is no rule, all can through.
        return true;

    if (rid)
        *rid = -1;
    bool is_use_whitelist = (bool)frip->stat;
    bool is_in_rule = false;
    bool use_rule_mask = (inet_mask == 0);

    while (frip)
    {
        if (use_rule_mask)
            inet_mask = frip->inet_mask;
        if ((calc_inetid(frip->inet_ip, frip->inet_mask) == calc_inetid(inet_ip, inet_mask)) ||
                (frip->inet_ip == 0))
        {
			if (rid != 0)
				*rid = frip->id;
			is_in_rule = true;
			break;
        }

        frip = frip->next;
    }

    return !(is_in_rule ^ is_use_whitelist);
}

static bool
filter_accctl(fr_accctl *fraccctl, char *uname, int inet_sip, int inet_smask, int inet_dip, int inet_dmask, time_t t, int *rid)
{
    if (fraccctl == NULL)  // there is no rule, all can through.
        return true;

    if (uname == NULL)
        return false;

    if (rid)
        *rid = -1;
    bool is_use_whitelist = (bool)fraccctl->stat;
    bool is_in_rule = false;
    bool suse_rule_mask = (inet_smask == 0);
    bool duse_rule_mask = (inet_dmask == 0);

    while (fraccctl)
    {
        if ( (strcmp("*", fraccctl->uname) == 0) || (strcmp(fraccctl->uname, uname) == 0) ) 
        {
            if (suse_rule_mask)
                inet_smask = fraccctl->inet_smask;

            // if name is in rule, judge the ip
            if ( (calc_inetid(fraccctl->inet_sip, fraccctl->inet_smask) == calc_inetid(inet_sip, inet_smask)) || (fraccctl->inet_sip == 0) )
            {
                if (duse_rule_mask)
                    inet_dmask = fraccctl->inet_dmask;
                if ( (calc_inetid(fraccctl->inet_dip, fraccctl->inet_dmask) == calc_inetid(inet_dip, inet_dmask)) || (fraccctl->inet_dip == 0) )
                {
					is_in_rule = is_time_in_rule(t, fraccctl->t_beg, fraccctl->t_end, fraccctl->t_mode);
                }
            }
        }

        if (is_in_rule)
        {
            if (rid != NULL)
                *rid = fraccctl->id;
            break;
        }
        fraccctl = fraccctl->next;
    }

    return !(is_in_rule ^ is_use_whitelist);
}

static bool
regex_match(char *reg_exp, int reg_flag, char *string)
{
    if (reg_exp == 0 || string == 0)
        return false;

    bool match_success = false;
    regex_t regex;
    regmatch_t pm[1];

    if (regcomp(&regex, reg_exp, reg_flag) != 0)
        return false;

    if (regexec(&regex, string, sizeof(pm)/sizeof(regmatch_t), pm, 0) == 0)
    {
        match_success = true;
    }

    regfree(&regex);

    return match_success;
}

static bool
filter_string(fr_string *frstring, char *string, int len, int direct, int *rid)
{
    if (frstring == 0)  // there is no rule, all can through.
        return true;
    if (string == NULL)
        return false;

    if (rid)
        *rid = -1;
    bool str_found = false;

    while (frstring)
    {
        if (frstring->direct == direct)
        {
            if ( ! frstring->is_regular)
            {
                if (strnstr(string, frstring->expr, len, frstring->sensitive) != 0)
                {
                    str_found = true;
                    if (rid != 0)
                        *rid = frstring->id;
                    break;
                }
            }
            else if (regex_match(frstring->expr, frstring->reg_flag, string))
            {
                str_found = true;
                if (rid != 0)
                    *rid = frstring->id;
                break;
            }
        }

        frstring = frstring->next;
    }

    return !str_found;
}

static bool
filter_ctrlcmd(fr_ctrlcmd *frctrlcmd, char *cmd, int len, int *rid)
{
    if (frctrlcmd == NULL)  // there is no rule, all can through.
        return true;
    if ((cmd == 0) || (len < 0))
        return false;

    if (rid)
        *rid = -1;
    bool is_use_whitelist = (bool)frctrlcmd->stat;
    bool cmd_found = false;
	bin_cmd *pBinCmd = NULL;

    for (; frctrlcmd != NULL; frctrlcmd = frctrlcmd->next)
    {
		pBinCmd = frctrlcmd->bcmd;
		if (pBinCmd == NULL)
			continue;
		if (pBinCmd->pos == (u16)-1)	// is string command
		{
			if (strnstr(cmd, pBinCmd->cmd, -1, frctrlcmd->sensitive) != NULL)
			{
				cmd_found = true;
				if (rid != NULL)
					*rid = frctrlcmd->id;
				break;
			}
		}
		else // is binary command
		{
			while (pBinCmd != NULL)
			{
				if (memcmp(cmd + pBinCmd->pos - 1, pBinCmd->cmd, pBinCmd->len) != 0)
					break;
				pBinCmd = pBinCmd->next;
			}
			if (pBinCmd == NULL)
			{
				cmd_found = true;
				if (rid != NULL)
					*rid = frctrlcmd->id;
				break;
			}
		}
    }

    return !(cmd_found ^ is_use_whitelist);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////
// Interface

FILTER*
create_filter(char *db_ip, int db_port, char *db_user, char *db_pass, char *db_name, unsigned int timeout_sec)
{
    FILTER *flt = (FILTER*)malloc(sizeof(FILTER));
    if (flt != 0)
    {
        memset(flt, 0, sizeof(FILTER));
        flt->is_loaded = false;
        // prepare MYSQL
        // mysql_library_init(num_elements, server_options, server_groups);
        mysql_library_init(0,0,0);
        flt->db_timeout_sec = timeout_sec;

        strncpy(flt->db_ip, db_ip, sizeof(flt->db_ip) - 1);
        flt->db_port = db_port;
        strncpy(flt->db_uname, db_user, sizeof(flt->db_uname) - 1);
        strncpy(flt->db_pass, db_pass, sizeof(flt->db_pass) - 1);
        strncpy(flt->db_dbname, db_name, sizeof(flt->db_dbname) - 1);
    }

    return flt;
}

void
destroy_filter(FILTER **flt)
{
	if ((flt == 0) || (*flt == 0))
		return;
    // unload the mysql library
    mysql_library_end();
    // free rules' memory
    free_flt_rules(&((*flt)->fr));
    // free filter
    free(*flt);

    // zero the pointer
    *flt = 0;
}

bool
load_filter_rules(FILTER *flt, const char *svrid)
{ 
    if (flt->is_loaded)
        return false;

    if ( (flt->ptr_mysql = mysql_init(0)) == 0)
        return false;

    mysql_options(flt->ptr_mysql, MYSQL_OPT_CONNECT_TIMEOUT, (const char*)&(flt->db_timeout_sec));
    if (mysql_real_connect(flt->ptr_mysql, flt->db_ip, flt->db_uname, flt->db_pass, flt->db_dbname, flt->db_port, 0,0) == 0)
    {
        MYSQL_ERR_OUT(flt->ptr_mysql);
        return false;
    }

    if (flt->fr != 0)	// not needed.
        free_flt_rules(&(flt->fr));
    flt->fr = alloc_flt_rules();

    if (flt->fr == 0)
        return false;

    strncpy(flt->fr->svrid, svrid, sizeof(flt->fr->svrid) - 1);
    if ( ! load_fr_time(flt))
	{
        //INF_OUT("初始过虑规则:[时间]过滤规则中无数据！");
	}
    else
	{
        //INF_OUT("初始过虑规则:[时间]过滤规则加载成功！");
	}

    if ( ! load_fr_sip(flt))
	{
        //INF_OUT("初始过虑规则:[源IP]过滤规则中无数据！");
	}
    else
	{
        INF_OUT("初始过虑规则:[源IP]过滤规则加载成功！");
	}

    if ( ! load_fr_dip(flt))
	{
        //INF_OUT("初始过虑规则:[目的IP]过滤规则中无数据！");
	}
    else
	{
        //INF_OUT("初始过虑规则:[目的IP]过滤规则加载成功！");
	}

    if ( ! load_fr_accctl(flt))
	{
        //INF_OUT("初始过虑规则:[访问控制]过滤规则中无数据！");
	}
    else
	{
        //INF_OUT("初始过虑规则:[访问控制]过滤规则加载成功！");
	}

    if ( ! load_fr_string(flt))
	{
        //INF_OUT("初始过虑规则:[关键字]过滤规则中无数据！");
	}
    else
	{
        //INF_OUT("初始过虑规则:[关键字]过滤规则加载成功！");
	}

    if ( ! load_fr_ctrlcmd(flt))
	{
        //INF_OUT("初始过虑规则:[控制信令]过滤规则中无数据！");
	}
    else
	{
        //INF_OUT("初始过虑规则:[控制信令]过滤规则加载成功！");
	}

	flt->fr->frproto.bEnable = false;
	flt->fr->frproto.efr_proto = FRP_NONE;
    flt->is_loaded = true;
    mysql_close(flt->ptr_mysql);

    return true;
}

bool
enable_proto_filter(FILTER *flt, enum __e_proto_type efr_proto, enum __flt_bw_type stat)
{
	if ((flt == NULL) || (flt->fr == NULL))
		return false;

    //printf("efr_proto val:%d\n", efr_proto);

	flt->fr->frproto.bEnable = true;
	flt->fr->frproto.stat = stat;
	flt->fr->frproto.efr_proto = efr_proto;

    /*
	if ((efr_proto & FRP_AMPLESKY) == FRP_AMPLESKY)
        printf("has found! 1\n");
	if ((flt->fr->frproto.efr_proto & FRP_AMPLESKY) == FRP_AMPLESKY)
        printf("has found! 2\n");
        */
	return true;
}

bool
reload_filter_rules(FILTER *flt, char *svrid)
{
    free_flt_rules(&(flt->fr));
    flt->is_loaded = false;
    return load_filter_rules(flt, svrid);
}

FILTER*
create_filter_wl(char *db_ip, int db_port, char *db_user, char *db_pass, char *db_name, unsigned int timeout_sec, const char *svrid)
{
    FILTER *flt = create_filter(db_ip, db_port, db_user, db_pass, db_name, timeout_sec);
    if (flt == 0)
        return 0;

    if ( ! load_filter_rules(flt, svrid))
        destroy_filter(&flt);

    return flt;
}

//--------------------------------
// rules filter
bool
filter_check(FILTER *flt, flt_item *fi)
{
    if ( (flt == 0) || !(flt->is_loaded))
        return false;

    const static char c2s[] = "客户端->服务端";
    const static char s2c[] = "服务端->客户端";

    char stime[64] = {0};
    char *uname = 0;
    char ssip[16] = {0};
    char ssmask[16] = {0};
    char sdip[16] = {0};
    char sdmask[16] = {0};

    char stmp[32] = {0};
    char *cmd = NULL;
	////
	time_t tnow = time(0);
    struct tm ltm;
    localtime_r(&tnow, &ltm);
	sprintf(stime, "%d年%d月%d日 %d时%d分", ltm.tm_year + 1900, ltm.tm_mon + 1, ltm.tm_mday, ltm.tm_hour, ltm.tm_min);
	////
    uname = fi->uname;
    inet_ntop(AF_INET, &(fi->inet_sip), ssip, 15);
    inet_ntop(AF_INET, &(fi->inet_smask), ssmask, 15);
    inet_ntop(AF_INET, &(fi->inet_dip), sdip, 15);
    inet_ntop(AF_INET, &(fi->inet_dmask), sdmask, 15);
    strncpy_safe(stmp, fi->str, sizeof(stmp) - 1);
    cmd = ((fi->ctrlcmd == 0) ? EMPTY_STR : fi->ctrlcmd);

    if ((fi->chk_flag & FIF_IVD_ALL) == FIF_IVD_ALL)
    {
#ifdef LOG_THROUGH
        SYS_INF("过滤器检测：全部通过，(用户名:%s, 源IP%s, 源掩码:%s, 目的IP:%s, 目的掩码:%s, 字符串:%s, 方向:%s, 控制信令:%s\n", 
                uname, ssip, ssmask, sdip, sdmask, stmp, ((fi->direct_str == FILTER_DIR_C2S)?c2s:s2c), cmd);
#endif
        return true;
    }

    // if any filter item is null, it will be ignored. and all the inputs of that item can be passed.
    flt_rules *frule = flt->fr;
    int mid = -1;	// matched id. if -1, matched none.
    if ((fi->chk_flag & FIF_CHK_TIME) == FIF_CHK_TIME)
    {
        if ( ! filter_time(frule->pfr_time, fi->tm, &mid))
        {
            SYS_WAR("过滤器检测:<时间规则(ID:%d)--阻止>(时间:%s)", mid, stime);
            return false;
        }
    }
    if ((fi->chk_flag & FIF_CHK_SIP) == FIF_CHK_SIP) 
    {
        if ( ! filter_ip(frule->pfr_sip, fi->inet_sip, fi->inet_smask, &mid))
        {
            SYS_WAR("过滤器检测:<源IP规则(ID:%d)--阻止>(源IP:%s)", mid, ssip);
            return false;
        }
    }
    if ((fi->chk_flag & FIF_CHK_DIP) == FIF_CHK_DIP)
    {
        if ( ! filter_ip(frule->pfr_dip, fi->inet_dip, fi->inet_dmask, &mid))
        {
            SYS_WAR("过滤器检测:<目的IP规则(ID:%d)--阻止>(目的IP:%s)", mid, sdip);
            return false;
        }
    }
    if ((fi->chk_flag & FIF_CHK_ACCCTL) == FIF_CHK_ACCCTL)
    {
        if ( ! filter_accctl(frule->pfr_accctl, fi->uname, fi->inet_sip, fi->inet_smask, fi->inet_dip, fi->inet_dmask, fi->tm, &mid))
        {
            SYS_WAR("过滤器检测:<访问控制规则(ID:%d)--阻止>(用户名:%s, 源IP:%s, 目的IP:%s, 时间:%s)", 
                                                    mid, uname, ssip, sdip, stime);
            return false;
        }
    }
    if ((fi->chk_flag & FIF_CHK_STRING) == FIF_CHK_STRING)
    {
        if ( ! filter_string(frule->pfr_string, fi->str, fi->len_str, fi->direct_str, &mid))
        {
            SYS_WAR("过滤器检测:<关键字规则(ID:%d)--阻止>(字符串:%s, 方向:%s)",
                                                    mid, stmp, ((fi->direct_str == FILTER_DIR_C2S)?c2s:s2c));
            return false;
        }
    }
    if ((fi->chk_flag & FIF_CHK_CTRLCMD) == FIF_CHK_CTRLCMD)
    {
        if ( ! filter_ctrlcmd(frule->pfr_ctrlcmd, fi->ctrlcmd, fi->len_ctrlcmd,  &mid))
        {
            SYS_WAR("过滤器检测:<控制信令规则(ID:%d)--阻止>(信令:%s)", mid, cmd);
            return false;
        }
    }
	if ((fi->chk_flag & FIF_CHK_PROTO) == FIF_CHK_PROTO)
	{
		bool bMatched = false;
		enum __e_proto_type ptype = FRP_NONE;
		char str_proto_type[16] = {"Unknown"};
	

		ptype = proto_type(fi->str, fi->len_str, str_proto_type);
        printf("ptype: %d, %s \n", ptype, str_proto_type);
		do
		{
			if (((frule->frproto.efr_proto & ptype) == FRP_HTTP))
			{
				bMatched = true;
				break;
			}
			if (((frule->frproto.efr_proto & ptype) == FRP_FTP))
			{
				bMatched = true;
				break;
			}
			if (((frule->frproto.efr_proto & ptype) == FRP_SIP)) 
			{
				bMatched = true;
				break;
			}
			if (((frule->frproto.efr_proto & ptype) == FRP_RTSP))
			{
				bMatched = true;
				break;
			}
			if (((frule->frproto.efr_proto & ptype) == FRP_AMPLESKY))
			{
                //puts("ampleaky matched!!!!!!!!!!!!!!!!!!!!!!");
				bMatched = true;
				break;
			}
		}while(0);
		
		if ((bMatched ^ frule->frproto.stat))
		{
            SYS_WAR("过滤器检测:<协议类型规则--阻止>(协议:%s)", str_proto_type);
			return false;
		}
	}

    return true;
}

bool
fltck_otm(FILTER *flt, time_t t)
{
    flt_item fi;
    init_flti_otm(&fi, t);
    return filter_check(flt, &fi);
}

bool
fltck_osip(FILTER *flt, int inet_ip, int inet_mask)
{
    flt_item fi;
    init_flti_osip(&fi, inet_ip, inet_mask);
    return filter_check(flt, &fi);
}

bool
fltck_odip(FILTER *flt, int inet_ip, int inet_mask)
{
    flt_item fi;
    init_flti_odip(&fi, inet_ip, inet_mask);
    return filter_check(flt, &fi);
}

bool
fltck_oacl(FILTER *flt, char *uname, time_t t, int inet_sip, int inet_smask, int inet_dip, int inet_dmask)
{
    flt_item fi;
    init_flti_oacl(&fi, uname, t, inet_sip, inet_smask, inet_dip, inet_dmask);
    return filter_check(flt, &fi);
}

bool
fltck_full_acl(FILTER *flt, char *uname, time_t t, int inet_sip, int inet_smask, int inet_dip, int inet_dmask)
{
    flt_item fi;
    init_flti_oacl(&fi, uname, t, inet_sip, inet_smask, inet_dip, inet_dmask);
    //fi.chk_flag = ~(FIF_IVD_TIME | FIF_IVD_SIP | FIF_IVD_DIP | FIF_IVD_ACCCTL);
    fi.chk_flag = (enum __flt_chk_flg)(FIF_CHK_TIME & FIF_CHK_SIP & FIF_CHK_DIP & FIF_CHK_ACCCTL);
    return filter_check(flt, &fi);
}

bool
fltck_ostr(FILTER *flt, char *str, int len_str, int str_direct)
{
    flt_item fi;
    init_flti_ostr(&fi, str, len_str, str_direct);
    return filter_check(flt, &fi);
}

bool
fltck_ocmd(FILTER *flt, char *ctrlcmd)
{
    flt_item fi;
    init_flti_ocmd(&fi, ctrlcmd, 0);
    return filter_check(flt, &fi);
}

bool 
fltck_oproto(FILTER *flt, char *proto, int len_proto)
{
	flt_item fi;
	init_flti_oproto(&fi, proto, len_proto);
	return filter_check(flt, &fi);
}

//--------------------------------
// initialize filter item

flt_item*
init_flti(flt_item *fi, time_t t, char *uname, int inet_sip, int inet_smask, int inet_dip, int inet_dmask, char *ctrlcmd, char *str, int len_str, int str_direct, int chk_flag)
{
    if (fi != 0)
    {
        memset(fi, 0, sizeof(flt_item));

        fi->tm = t;
        fi->inet_sip = inet_sip;
        fi->inet_smask = inet_smask;
        fi->inet_dip = inet_dip;
        fi->inet_dmask = inet_dmask;

        if (uname != 0)
            strncpy(fi->uname, uname, sizeof(fi->uname) - 1);
        fi->ctrlcmd = ctrlcmd;
        fi->str = str;
        fi->len_str = len_str;
        fi->direct_str = str_direct;

        fi->chk_flag = (enum __flt_chk_flg)chk_flag;
    }

    return fi;
}

flt_item*
init_flti_otm(flt_item *fi, time_t t)
{
    if (fi != 0)
    {
        memset(fi, 0, sizeof(flt_item));
        fi->tm = t;

        fi->chk_flag = FIF_CHK_TIME;
    }
    return fi;
}


flt_item*
init_flti_osip(flt_item *fi, int inet_ip, int inet_mask)
{
    if (fi != 0)
    {
        memset(fi, 0, sizeof(flt_item));
        fi->inet_sip = inet_ip;
        fi->inet_smask = inet_mask;

        fi->chk_flag = FIF_CHK_SIP;
    }
    return fi;
}

flt_item*
init_flti_odip(flt_item *fi, int inet_ip, int inet_mask)
{
    if (fi != 0)
    {
        memset(fi, 0, sizeof(flt_item));
        fi->inet_dip = inet_ip;
        fi->inet_dmask = inet_mask;

        fi->chk_flag = FIF_CHK_DIP;
    }
    return fi;
}

flt_item*
init_flti_oacl(flt_item *fi, char *uname, time_t t, int inet_sip, int inet_smask, int inet_dip, int inet_dmask)
{
    if (fi != 0)
    {
        memset(fi, 0, sizeof(flt_item));
        strncpy(fi->uname, uname, sizeof(fi->uname) - 1);

        fi->tm = t;
        fi->inet_sip = inet_sip;
        fi->inet_smask = inet_smask;
        fi->inet_dip = inet_dip;
        fi->inet_dmask = inet_dmask;

        fi->chk_flag = FIF_CHK_ACCCTL;
    }
    return fi;
}

flt_item*
init_flti_ostr(flt_item *fi, char *str, int len_str, int direct)
{
    if (fi != 0)
    {
        memset(fi, 0, sizeof(flt_item));
        fi->str = str;
        fi->len_str = len_str;
        fi->direct_str = direct;

        fi->chk_flag = FIF_CHK_STRING;
    }
    return fi;
}

flt_item*
init_flti_ocmd(flt_item *fi, char *ctrlcmd, int len_cmd)
{
    if (fi != NULL)
    {
        memset(fi, 0, sizeof(flt_item));
        fi->ctrlcmd = ctrlcmd;
		fi->len_ctrlcmd = len_cmd;

        fi->chk_flag = FIF_CHK_CTRLCMD;
    }
    return fi;
}

flt_item*
init_flti_oproto(flt_item *fi, char *proto, int len_proto)
{
	if (fi != NULL)
	{
		memset(fi, 0, sizeof(flt_item));
		fi->str = proto;
		fi->len_str = len_proto;

		fi->chk_flag = FIF_CHK_PROTO;
	}
	return fi;
}

FILTER*
get_filter(const char *svrid)
{
	if (svrid == NULL)
		return NULL;

	char ip[32] = {0};
	char port[32] = {0};
	char user[32] = {0};
	char pwd[32] = {0};
	get_db_property(ip, port, user, pwd);

	return create_filter_wl(ip, atoi(port), user, pwd, (char*)DB_NAME, 0, svrid);
}

/*
 * node: control_type describle the control mode what
 * base user control or base global control.
 * sip:  the ip of visit client.
 * dip:  the video server ip.
 */
int 
control_user_filter(FILTER *g_flt, char **ut_buf, char *user, u32 sip, u32 dip, int control_type)
{
	time_t tnow;
	char   cmd[128];

	//global time filter
	tnow = time(NULL);
	if (!fltck_otm(g_flt, tnow))
		return -1;

	// global src ip filter
	if (!fltck_osip(g_flt, sip, 0))
		return -1;

	// global des ip filter
	if (!fltck_odip(g_flt, dip, 0))
		return -1;

	if (control_type ==	FILTER_USER) {
		// user filter
		if (!fltck_oacl(g_flt, user, tnow, sip, 0, dip, 0))
			return -1;
	}

	//global protocol filter
	sscanf(*ut_buf, "%[^\r\n]", cmd);
	if (fltck_ocmd(g_flt,cmd))
		return -1;
	
	//global key filter
	if (!fltck_ostr(g_flt, *ut_buf, -1, 1))
		return -1;

	return 0;
}

//
// protocol type filter
//

static bool fr_is_http(char *proto, int len)
{
	char *ptr = NULL;
	if ((ptr = strnstr(proto, (char*)"HTTP/", len, false)) == NULL)
		return false;

	if ((ptr = strnstr(ptr, (char*)"Host:", len - (ptr - proto), false)) == NULL)
		return false;

	if ((ptr = strnstr(ptr, (char*)"\r\n\r\n", len - (ptr - proto) , true)) == NULL)
		return false;

	return true;
}

static bool fr_is_ftp(char *proto, int len)
{
	static const char FTP_RES_FLAG[] = "FILTER_FTP_FLAG";
	tdata *t_data = NULL;
	bool res = false;
	if ((t_data = tp_get_data(FTP_RES_FLAG)) != NULL)
	{
		res = (bool)(*(t_data->data));
	}
	else
	{
		res = (strncmp(proto, (char*)"USER ", sizeof("USER ")-1) == 0);
		tp_set_data(FTP_RES_FLAG, (const char*)&res, sizeof(bool));
	}

	return res;
}

static bool fr_is_sip(char *proto, int len)
{
	char *ptr = NULL;
	if ((ptr = strnstr(proto, (char*)"<sip:", len, false)) == NULL)
		return false;
	if ((ptr = strnstr(ptr, (char*)"\r\n\r\n", len - (ptr - proto), true)) == NULL)
		return false;
	return true;
}

static bool fr_is_rtsp(char *proto, int len)
{
	const static int offset_limit = 40;
	char *ptr = NULL;
	if ((ptr = strnstr(proto, (char*)"rtsp://", ((len > offset_limit) ? offset_limit : len), false)) == NULL)
		return false;
	if ((ptr = strnstr(ptr, (char*)"CSeq:", len - (ptr - proto), false)) == NULL)
		return false;
	if ((ptr = strnstr(ptr, (char*)"\r\n\r\n", len - (ptr - proto), true)) == NULL)
		return false;
	return true;
}

static bool fr_is_amplesky(char *proto, int len)
{
    // eg:
    // 00000000  30 30 30 38 35 52 5f 49  44 3d 39 35 38 3a 4f 50 00085R_I D=958:OP
    // 00000010  3d 32 30 30 33 3a 44 5f  4e 41 4d 45 3d 44 45 56 =2003:D_ NAME=DEV
    // 00000020  49 43 45 53 3a 44 5f 4b  65 79 3d 64 34 66 37 36 ICES:D_K ey=d4f76
    // 00000030  64 66 64 66 64 33 61 65  36 31 66 3a 4d 5f 55 49 dfdfd3ae 61f:M_UI
    // 00000040  44 3d 64 34 66 37 36 64  66 64 66 64 33 61 65 36 D=d4f76d fdfd3ae6
    // 00000050  31 66 30 3a 42 5f 49 50  3d 3a                   1f0:B_IP =:

    const static char FLG_RID[] = "R_ID=";
    const static char FLG_OP[] = "OP=";
    char field_for_len[8] = {0};
    
    memcpy(field_for_len, proto, 5);
    if (atoi(field_for_len) == 0)
        return false;
    if (strnstr(proto, FLG_RID, len, true) == NULL)
        return false;
    if (strnstr(proto, FLG_OP, len, true) == NULL)
        return false;

	return true;
}

static enum __e_proto_type proto_type(char *proto, int len, char type[16])
{
	const static char s_type[][16] = 
	{
		"Unknown",
		"HTTP",
		"SIP",
		"FTP",
		"RTSP",
        "AMPLESKY", // 天地阳光
	};

	enum __e_proto_type nProtoType = FRP_NONE;
	if ((proto == NULL) || (len <= 0))
		return FRP_NONE;

	int idx = 1;
	do
	{
        //++idx;
		if (fr_is_http(proto, len))
		{
			//idx = 1;
			nProtoType = FRP_HTTP;
			break;
		}
        ++idx;
		if (fr_is_sip(proto, len))
		{
			//idx = 2;
			nProtoType = FRP_SIP;
			break;
		}
        ++idx;
		if (fr_is_ftp(proto, len))
		{
			//idx = 3;
			nProtoType = FRP_FTP;
			break;
		}
        ++idx;
		if (fr_is_rtsp(proto, len))
		{
			//idx = 4;
			nProtoType = FRP_RTSP;
			break;
		}
        ++idx;
        if (fr_is_amplesky(proto, len))
        {
            nProtoType = FRP_AMPLESKY;
            break;
        }
        // there is no protocol matched.
        idx = 0;
	}while(0);
	strcpy(type, s_type[idx]);

	return nProtoType;
}

//
// Load protocol type filter
//

bool
load_proto_type_filter(FILTER *flt)
{
	query_conf *pconf = NULL;
	query_conf *pctrl = NULL;
	char cfg_path[256] = {0};
	char *val = NULL;
    int nval = 0;
    int flag = 0;

	sprintf(cfg_path, "%s/%s", "/topconf/topvp", "protocol.conf");
    
	if ((pconf = load_configuration(cfg_path)) == NULL)
	{
        logwar_out("Load protocol control config file failed!");
        return false;
	}

	if ((pctrl = find_label(pconf, (char*)"id")) == NULL)
	{
		free_configuration(&pconf);
		logwar_out("Find protocol control id failed!");
		return false;
	}

    if ((val = get_value_from_label(pctrl, (char*)"sipflag")) != NULL)
        nval = atoi(val);
    if (nval > 0)
        flag |= FRP_SIP;

    if ((val = get_value_from_label(pctrl, (char*)"httpflag")) != NULL)
        nval = atoi(val);
    if (nval > 0)
        flag |= FRP_HTTP;

    if ((val = get_value_from_label(pctrl, (char*)"rtspflag")) != NULL)
        nval = atoi(val);
    if (nval > 0)
        flag |= FRP_RTSP;

    if ((val = get_value_from_label(pctrl, (char*)"ampleskyflag")) != NULL)
        nval = atoi(val);
    if (nval > 0)
        flag |= FRP_AMPLESKY;

    if ( ! enable_proto_filter(flt, (enum __e_proto_type)flag, FILTER_WHITELIST))
    {
        logwar_out("Init protocol type filter failed!");
        return false;
    }

    return true;
}

