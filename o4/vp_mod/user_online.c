#include "../vp_sdk/vpsdk.h"
#include "mod_mysql.h"
#include "user_online.h"

const static char online_tb[] = "vgap_onlineuser";

void
user_online(const char *uname, char *client_ip, const char *service_id)
{
	char query[1024] = {0};

	if ( ! modmysql_isopen())
		return;

	MYSQL *mysql = modmysql_get_freeconn();
	if (mysql == 0)
		return;
	
    sprintf(query, "insert into %s(online_username, online_ip, online_serviceid) values('%s', '%s', '%s')", online_tb, uname, client_ip, service_id); 
    mysql_real_query(mysql, query, strlen(query));

	modmysql_return_conn(mysql);
}

void
user_offline(const char *uname, char *client_ip, const char *service_id)
{
	MYSQL_RES * res = 0;
	MYSQL_ROW record;
	char query[1024] = {0};

	if ( ! modmysql_isopen())
		return;

	MYSQL *mysql = modmysql_get_freeconn();
	if (mysql == 0)
		return;

	sprintf(query, "select online_id from %s where online_username='%s' and online_ip='%s' and online_serviceid='%s' limit 0,1",
			online_tb, uname, client_ip, service_id);

	if (mysql_real_query(mysql, query, strlen(query)) == 0)
	{
		if ( (res = mysql_store_result(mysql)) != 0)
		{
			if ( (record = mysql_fetch_row(res)) != 0)
			{
				sprintf(query, "delete from %s where online_id='%s'", online_tb, record[0]); 
				mysql_real_query(mysql, query, strlen(query));
			}
			mysql_free_result(res);
		}
	}
	
	modmysql_return_conn(mysql);
}

int
user_is_online(char *uname)
{
	int is_online = 0;
    MYSQL_RES* res = 0;
	char query[1024] = {0};

	MYSQL *mysql = modmysql_get_freeconn();
	if (mysql == 0)
		return -1;

    sprintf(query, "select * from %s where online_username='%s'", online_tb, uname); 
    if ( mysql_real_query(mysql, query, strlen(query)) == 0)
	{
		res = mysql_store_result(mysql);
		if (res != 0)
		{
			if (mysql_num_rows(res) > 0)
				is_online = 1;

			mysql_free_result(res);
		}
	}
	modmysql_return_conn(mysql);
	return is_online;
}

void user_clear_online()
{
	char query[1024] = {0};

	MYSQL *mysql = modmysql_get_freeconn();
	if (mysql == 0)
    {
        logdbg_out("user_clear_online: get free mysql pointer failed!");
		return;
    }

    sprintf(query, "delete from %s", online_tb); 
    mysql_real_query(mysql, query, strlen(query));
	modmysql_return_conn(mysql);
}

