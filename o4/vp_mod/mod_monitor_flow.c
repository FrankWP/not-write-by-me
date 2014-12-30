#include "../vpheader.h"
#include "mod_monitor_flow.h"
#include "mod_mysql.h"

#define FLOWCONF "./flow.conf"

#define FSTIPROW    20
#define FSTIPCOL    16

static const char QUERY_PRE_SERV_IP[] = "SELECT firstip_supplier_id, firstip_value FROM vgap_firstip_conf";
static const char QUERY_PRE_MAX_RATE[] = "SELECT pro_supplier_id, pro_flowsize FROM vgap_provider";
static const char QUERY_PRE_SUPP_ID[] = "SELECT service_conf, pro_supplier_id FROM vgap_service_conf";

static int maxrate = 0;
static int mem_flg = 0;
static int fstip_record_row = 0;
static int get_sql_dat_flg = 0;

const static int high_rate_minlast = 3;
static char fst_ip_val[FSTIPROW][FSTIPCOL] = {{0}};

int query_prio_ips(u32 plat_id, char *_supp_id)
{
    int n = 0;
    int j = 0;
    int num_row = 0;
    char plat_id_str[32] = {0};
    char supp_id[16] = {0};

    MYSQL       *mysqlconn;
    MYSQL_RES   *mysqlresult;
    MYSQL_ROW   mysqlrow;

    inet_ultoa(plat_id, plat_id_str);
    
    if ((mysqlconn = modmysql_get_freeconn()) == NULL){
        loginf_out("moniter flow connect MySql failed!");
        return -1;
    }

    if ((mysql_real_query(mysqlconn, QUERY_PRE_SUPP_ID, sizeof(QUERY_PRE_SUPP_ID) )) != 0){
        loginf_out("moniter flow query first ip supplier id failed!");
        return -1;
    }

    mysqlresult = mysql_store_result(mysqlconn);
    if (mysqlresult){
        num_row = mysql_num_rows(mysqlresult);
    }

    for (n = 0; n < num_row; n++)
    {
        mysqlrow = mysql_fetch_row(mysqlresult);
        if (strcmp(plat_id_str, mysqlrow[0]) == 0){
            strncpy(supp_id, mysqlrow[1], strlen(mysqlrow[1]));
            strncpy(_supp_id, mysqlrow[1], strlen(mysqlrow[1]));
            break;
        }
    }

    if ((mysql_real_query(mysqlconn, QUERY_PRE_SERV_IP, sizeof(QUERY_PRE_SERV_IP) )) != 0){
        loginf_out("moniter flow query first ip address list failed!");
        return -1;
    }

    mysqlresult = mysql_store_result(mysqlconn);
    if (mysqlresult){
        num_row = mysql_num_rows(mysqlresult);
    }

    for (n=0, j=0; n < num_row; n++)
    {
        mysqlrow = mysql_fetch_row(mysqlresult);
        if (strcmp(supp_id, mysqlrow[0]) == 0){
            strncpy(fst_ip_val[j], mysqlrow[1], strlen(mysqlrow[1]));
            j++;
        }
    }
    fstip_record_row = j;

    mysql_free_result(mysqlresult);
    modmysql_return_conn(mysqlconn);

    return 0;
}

int is_ip_in_fstip(u32 src_ip)
{
    int n;
    int flag = 0;
    char src_ip_str[16] = {0};
    inet_ultoa(src_ip, src_ip_str);

    for (n=0; n<fstip_record_row; n++){
        if (strncmp(fst_ip_val[n], src_ip_str, strlen(src_ip_str)) == 0){
            flag = 1;
            break;
        }
    }

    return flag;
}

static int read_mem_flow_conf(char *pmem, int* flow_rate)
{
    char tmp[128] = {0};

    char *p = strstr(pmem, "Total Rate: ");
    if (p != NULL){
        sscanf(p+strlen("Total Rate: "), "%[^a-z ]", tmp);
        sscanf(tmp, "%d", flow_rate);
    }
    else
        return -1;

    return 0;
}

static char* create_flow_smem(const char * psmid)
{
    int fd, oflags;

    oflags = O_RDWR | O_CREAT | O_EXCL;
    fd = shm_open(psmid, oflags, FILE_MODE);
    if (fd == -1) {
        if (errno == EEXIST)
            fd = shm_open(psmid, O_RDWR, FILE_MODE);
        else
            return NULL;
    }

    char *pmem = (char*)mmap(NULL, 256,
                   PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    ftruncate(fd, 256);
    close(fd);

    return pmem;
}

/*
int get_max_flow_rate(u32 ipaddr)
{
    int n;
    int num_row;
    MYSQL       *mysqlconn;
    MYSQL_RES   *mysqlresult;
    MYSQL_ROW   mysqlrow;

    char ipaddr_str[16] = {0};
    inet_ultoa(ipaddr, ipaddr_str);

    if ((mysqlconn = modmysql_get_freeconn()) == NULL){
        loginf_out("获取数据库连接失败!");
        return -1;
    }

    if ((mysql_real_query(mysqlconn, QUERY_PRE_MAX_RATE, sizeof(QUERY_PRE_MAX_RATE) )) != 0){
        loginf_out("查寻.");
        return -1;
    }

    mysqlresult = mysql_store_result(mysqlconn);
    if (mysqlresult){
        num_row = mysql_num_rows(mysqlresult);
    }

    for (n = 0; n < num_row; n++)
    {
        mysqlrow = mysql_fetch_row(mysqlresult);
        
        if (strcmp(ipaddr_str, mysqlrow[0]) == 0){
            sscanf(mysqlrow[1], "%d", &maxrate);
            break;
        }
    }

    mysql_free_result(mysqlresult);
    modmysql_return_conn(mysqlconn);

	return 1;
}
*/

int get_max_flow_rate(char *_supp_id)
{
    int n;
    int num_row;
    MYSQL       *mysqlconn;
    MYSQL_RES   *mysqlresult;
    MYSQL_ROW   mysqlrow;

    if ((mysqlconn = modmysql_get_freeconn()) == NULL){
        loginf_out("获取数据库连接失败!");
        return -1;
    }

    if ((mysql_real_query(mysqlconn, QUERY_PRE_MAX_RATE, sizeof(QUERY_PRE_MAX_RATE) )) != 0){
        loginf_out("查寻.");
        return -1;
    }

    mysqlresult = mysql_store_result(mysqlconn);
    if (mysqlresult){
        num_row = mysql_num_rows(mysqlresult);
    }

    for (n = 0; n < num_row; n++)
    {
        mysqlrow = mysql_fetch_row(mysqlresult);
        
        if (strcmp(_supp_id, mysqlrow[0]) == 0){
            sscanf(mysqlrow[1], "%d", &maxrate);
            break;
        }
    }

    mysql_free_result(mysqlresult);
    modmysql_return_conn(mysqlconn);

	return 1;
}

/***priority ip interface***/
int ip_can_through(int *flg, u32 src_ip, time_t *t_old)
{
    if (flg == NULL || t_old == NULL || src_ip == 0)
        return 0;

    if (get_sql_dat_flg == 0)
	{
        *flg = THROUGH;
		return 0;
	}

    if (is_ip_in_fstip(src_ip)){
        *flg = THROUGH;
        return 0;
    }

    int     flow_rate = 0;
    int     t_interval = 0;
    char    *pmem;
    char    flow_log_info[128] = {0};

    time_t  t_now = time(NULL);

    if (mem_flg == 0){
        pmem = create_flow_smem("flow.conf");
        mem_flg = 1;
    }

    t_interval = t_now - *t_old;
    if (t_interval < 1)
    {
        *flg = THROUGH;
        return 0;
    }

    if (read_mem_flow_conf(pmem, &flow_rate) == -1)
        return 0;
    
    if (flow_rate < maxrate)
    {
        *flg = THROUGH;
        *t_old = t_now;
        return 0;
    }

    if (t_interval < high_rate_minlast)
    {
        *flg = THROUGH;
        return 0;
    }

    *t_old = t_now;
    sprintf(flow_log_info, "当前流量值：%d  最大流量限制：%d", flow_rate, maxrate);
    logwar_out(flow_log_info);

    *flg = CLOSE; 

    return 0;
}

/***priority ip interface***/
int init_prio_ip_para(u32 plat_id, u32 local_ip)
{
    if (get_sql_dat_flg == 0)
    {
        char _supp_id[16] = {0};

        if (query_prio_ips(plat_id, _supp_id) == -1)
            return -1;

        if (get_max_flow_rate(_supp_id) == -1)
            return -1;

        get_sql_dat_flg = 1;
    }

    return 0;
}

