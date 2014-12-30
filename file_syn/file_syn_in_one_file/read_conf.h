#include "syshead.h"

typedef struct __conf_item
{
    char *item_name;
    char *item_value;
    struct __conf_item *item_next;
} conf_item;

typedef struct __query_conf
{
    char *label_name;
    conf_item *label_item;
    struct __query_conf *label_next;
} query_conf;

struct sock_conf
{
	unsigned int s_ip;
	unsigned short s_port;
};


char* trim(char *str);
static conf_item *deal_with_item_line(char *read_line, query_conf **p_conf_que, conf_item **p_item_tail);
query_conf *find_label(query_conf *p_query_conf, char *label_name);

char *get_value_from_label(query_conf *que, char *item_name);
unsigned int inet_atoul(const char * s);
char * inet_ultoa(unsigned int u, char * s);
char* line_from_buf(char *cursor, char *store, int storesz);
query_conf * load_configuration(const char *filepath);
char *pre_deal_with_line(char *line);
void free_configuration(query_conf **pque);

int init_conf();
int init_sock(unsigned int s_ip, unsigned short s_port);
void start_to_trans_file(int argc, char **argv);

void deal_all_item_value(query_conf *que, char *item_name);
int get_fname_from_args(char* file_name);
void parse_fname(int argc, char **argv);
int send_data(char *send_buf, int send_len);

//////////////////md5
typedef unsigned long int UINT4;

typedef struct {
	UINT4 i[2];                   /* number of _bits_ handled mod 2^64 */
	UINT4 buf[4];                                    /* scratch buffer */
	unsigned char in[64];                              /* input buffer */
	unsigned char digest[16];     /* actual digest after MD5Final call */
} MD5_CTX;

void MD5Init ();
void MD5Update ();
void MD5Final ();

static void Transform ();
