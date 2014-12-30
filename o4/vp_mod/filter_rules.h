#ifndef	_FILTER_RULES_H_
#define _FILTER_RULES_H_

#include "../vpheader.h"
#include "mod_mysql.h"

#define FILTER_USER          0x00
#define FILTER_GLOBAL        0x01
#define	FILTER_DIR_S2C		 0
#define	FILTER_DIR_C2S		 1

typedef struct __flt_item	flt_item;
typedef struct __flt__		FILTER;

enum __flt_bw_type
{
	FILTER_BLACKLIST = 0,
	FILTER_WHITELIST = 1,
};

enum __flt_chk_flg
{
	FIF_IVD_NONE	= 0,	// Filter Item Flag: there isn't any item will out of work. all the rules will be in work.
    FIF_CHK_ALL     = 0,

	FIF_IVD_TIME	= 1,	// Filter Item Flag: InValiDate time item, it means time fileter rules will not work, all the time can pass.
	FIF_CHK_TIME	= ~1,	// Filter Item Flag: OnLY TIME filter rules will be in work.

	FIF_IVD_SIP		= 1 << 1,	// 2
	FIF_CHK_SIP		= ~(1 << 1),

	FIF_IVD_DIP		= 1 << 2,	// 4
	FIF_CHK_DIP		= ~(1 << 2),

	FIF_IVD_ACCCTL	= 1 << 3,	// 8
	FIF_CHK_ACCCTL	= ~(1 << 3),

	FIF_IVD_STRING	= 1 << 4,	// 16
	FIF_CHK_STRING	= ~(1 << 4),

	FIF_IVD_CTRLCMD	= 1 << 5,	// 32
	FIF_CHK_CTRLCMD	= ~(1 << 5),

	FIF_IVD_PROTO	= 1 << 6,	// 64
	FIF_CHK_PROTO	= ~(1 << 6), 

	FIF_IVD_ALL		= ~0,	// Filter Item Flag: InValiDate ALL the items, it means all the filter rules would not work.
};

enum __e_proto_type
{
    FRP_NONE	= 0,
    FRP_HTTP	= 1,
    FRP_FTP		= 1 << 1,
    FRP_SIP		= 1 << 2,
    FRP_RTSP	= 1 << 3,
    FRP_AMPLESKY= 1 << 4, // 天地阳光
    //FRP_HXHT    = 1 << 5, // hu xin hu tong 

    FRP_ALL		= ~0,
};

typedef struct __fr_time
{
	int id;
	int t_beg;
	int t_end;
	int t_mode;	// 0->hour; 1->week
	int stat;	// 0->black list; 1->white list
	
	struct __fr_time *next;
}fr_time;

typedef struct __fr_ip
{
	int id;
	u32 inet_ip;
	int inet_mask;
	int stat;	// 0->black list; 1->white list

	struct __fr_ip *next;
}fr_ip;

typedef struct __fr_accctl
{
	int id;
	char uname[128];
	int inet_sip;
	int inet_smask;
	int inet_dip;
	int inet_dmask;
	int t_beg;
	int t_end;
	int t_mode;	// 0->hour; 1->week
	int stat;	// 0->black list; 1->white list

	struct __fr_accctl *next;
}fr_accctl;

typedef struct __fr_string
{
	int id;
	int direct;
	bool is_regular;
    int  reg_flag;
    bool sensitive;
	char expr[1024];

	struct __fr_string *next;
}fr_string;

typedef struct __bin_cmd
{
	u16 pos;	// if -1, means any position.
	u16 len;
	char *cmd;

	struct __bin_cmd *next;
}bin_cmd;

typedef struct __fr_ctrlcmd
{
	int  id;
	char name[128];
	int  stat;	// 0->black list; 1->white list
    bool sensitive;
	bin_cmd *bcmd;

	struct __fr_ctrlcmd *next;
}fr_ctrlcmd;

typedef struct __fr_proto
{
	bool bEnable;
	int  stat;	// 0->black list; 1->white list
	enum __e_proto_type efr_proto;
}fr_proto;

typedef struct __flt_rules
{
	char		svrid[16];
	fr_time		*pfr_time;
	fr_ip		*pfr_sip;
	fr_ip		*pfr_dip;
	fr_accctl	*pfr_accctl;
	fr_string	*pfr_string;
	fr_ctrlcmd	*pfr_ctrlcmd;
	fr_proto	frproto;

	struct __flt_rules	*next;
}flt_rules;

struct __flt__
{
	// information about database that filter rules load from.
	int db_port;
	unsigned int db_timeout_sec;
	char db_ip[16];
	char db_uname[32];
	char db_pass[32];
	char db_dbname[32];
	MYSQL *ptr_mysql;
	// filter fules load from which path's files.
	//char rules_path[256];

	bool is_loaded;
	flt_rules *fr;
};

struct __flt_item
{
	time_t tm;
	char uname[32];
	int inet_sip;
	int inet_smask;
	int inet_dip;
	int inet_dmask;

	char *str;
    int direct_str;
    int len_str;

	char *ctrlcmd;
	int len_ctrlcmd;

	enum __flt_chk_flg chk_flag;
};

/////////////////////////////////////////////////////////////////////////////////
// functions

flt_item *init_flti(flt_item *fi, time_t t, char *uname, int inet_sip, int inet_smask, int inet_dip, int inet_dmask, char *ctrlcmd, char *str, int str_len, int str_direct, int chk_flag);
flt_item *init_flti_otm(flt_item *fi, time_t t);
flt_item *init_flti_osip(flt_item *fi, int inet_sip, int inet_smask);
flt_item *init_flti_odip(flt_item *fi, int inet_dip, int inet_dmask);
flt_item *init_flti_oacl(flt_item *fi, char *uname, time_t t, int inet_sip, int inet_smask, int inet_dip, int inet_dmask);
flt_item *init_flti_ostr(flt_item *fi, char *str, int len_str, int str_direct/*in or out*/);
flt_item *init_flti_ocmd(flt_item *fi, char *ctrlcmd, int len_cmd);
flt_item *init_flti_oproto(flt_item *fi, char *proto, int len_proto);

bool filter_check(FILTER *flt, flt_item *fi);

//----------------------------------
// these following functions are much commonly used.

FILTER *get_filter(const char *svrid);

FILTER *create_filter(char *db_ip, int db_port, char *db_user, char *db_pass, char *db_name, unsigned int timeout_sec);
void destroy_filter(FILTER **flt);
bool load_filter_rules(FILTER *flt, const char *svrid);
bool load_proto_type_filter(FILTER *flt);
bool reload_filter_rules(FILTER *flt, char *svrid);
bool enable_proto_filter(FILTER *flt, enum __e_proto_type efr_proto, enum __flt_bw_type stat);
// create filter with load.
FILTER *create_filter_wl(char *db_ip, int db_port, char *db_user, char *db_pass, char *db_name, unsigned int timeout_sec, const char *svrid);
int control_user_filter(FILTER *g_flt, char **ut_buf, char *user, u32 sip, u32 dip, int control_type);

bool fltck_otm(FILTER *flt, time_t);
bool fltck_osip(FILTER *flt, int inet_ip, int inet_mask);
bool fltck_odip(FILTER *flt, int inet_ip, int inet_mask);
bool fltck_oacl(FILTER *flt, char *uname, time_t t, int inet_sip, int inet_smask, int inet_dip, int inet_dmask);
bool fltck_full_acl(FILTER *flt, char *uname, time_t t, int inet_sip, int inet_smask, int inet_dip, int inet_dmask);
bool fltck_ostr(FILTER *flt, char *str, int len_str, int str_direct/*in or out*/);
bool fltck_ocmd(FILTER *flt, char *ctrlcmd);
bool fltck_oproto(FILTER *flt, char *proto, int len_proto);

#endif

