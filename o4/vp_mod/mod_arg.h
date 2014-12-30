#ifndef _MOD_ARG_H_
#define _MOD_ARG_H_

bool a_init(int argc, char *argv[], void(*exit_sys)(int), const char *logname);
void a_exit(int n);
int  a_get_pmid();
char *a_get_pmid_str();
int  a_get_ferry_port();
char *a_get_ferry_port_str();
char *a_get_cfgpath_portmap();

#endif  //  _MOD_ARG_H_

