#include "../vpheader.h"

static const char g_apps[] = "vp-fiber vp-vsudp vp-vstcp";
static const char g_pidfn[] = "sys-license.pid";

static void quit_system(int n)
{
	remove_pid_file(g_pidfn);
	closelog();

	exit(n);
}

int
main(int argc, char **argv)
{
    signal(SIGINT, quit_system);
    signal(SIGTERM, quit_system);
	
#ifndef  VP_DEBUG
	if (create_daemon() != 0)
		return 0;
#endif
	
	openlog("sys-license", LOG_CONS|LOG_PID|LOG_PERROR, LOG_USER);
	if (create_pid_file(g_pidfn) < 0)
	{
		syslog(LOG_INFO, "create pid file failed.");
		closelog();
		return -1;
	}
	
	long li_pid = start_license(quit_system);
	if (li_pid == -1)
	{
		syslog(LOG_INFO, "start license failed");
		quit_system(0);
		return -1;
	}
	pthread_join(li_pid, 0);	

	return 0;
}

