#ifndef	_USER_ONLINE_
#define	_USER_ONLINE_

void user_online(const char *uname, char *client_ip, const char *service_id);
void user_offline(const char *uname, char *client_ip, const char *service_id);
int user_is_online(char *uname);
// clear all online user in database
void user_clear_online();

#endif	//_USER_ONLINE_
