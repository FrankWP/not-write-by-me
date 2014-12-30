#ifndef	_MOD_TOOLS_
#define	_MOD_TOOLS_
#include "../vp_sdk/udeftype.h"

//void t_disbuf(const unsigned char *ptr, int len);
size_t t_getfilesz(FILE *f);
bool t_read_full_file_by_stream(FILE *pf, char **buf, size_t *sz_buf, size_t sz_limit);
bool t_read_full_file(const char *fpath, char **buf, size_t *bufsz, size_t szlimit);
bool t_backup_file(const char *fname, const char *info);
char *t_get_conf_line(char *buf, char *store);

#endif	//_MOD_TOOLS_

