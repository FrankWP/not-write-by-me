#ifndef	_MOD_MYSQL_H_
#define	_MOD_MYSQL_H_

#include <mysql/mysql.h>
#include "../vp_sdk/udeftype.h"

bool	get_db_property(char *ip, char *port, char *user, char *pwd);
bool	modmysql_isopen(void);
bool	modmysql_open(const char *dbname, int nConn);
void	modmysql_close(void);
void	modmysql_return_conn(MYSQL *mysql);
MYSQL*	modmysql_get_freeconn(void);

#endif	//_MOD_MYSQL_H_

