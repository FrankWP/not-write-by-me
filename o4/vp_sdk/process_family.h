#ifndef _PROCESS_FAMILY_H_
#define _PROCESS_FAMILY_H_

#define PF_DISMISSED 9999

pid_t pf_daemon();
bool pf_init_home();
bool pf_add_member(pid_t member_pid);
void pf_dismiss_member(pid_t member_pid);
void pf_destroy_home();

bool pf_init_member(void (*before_exit)(int), int exit_code);
void pf_away_home();

#endif

