#include "vpheader.h"

#define TIMEOUT 12

static void exit_sys(int signnum)
{
    closelog();
    destroy_portpool();
    _exit(0);
}

static void sig_segv(int signum)
{
    syslog(LOG_ERR, "Invalied memory operation.");
    _exit(-1);
}

static void sig_pipe(int signum)
{
    syslog(LOG_ERR, "Pipe broken.");
    _exit(-2);
}

int main(int argc, char *argv[])
{
    bool daemon = true;
    vp_uthtrans __ut;
    int     opt;
    char    *ferry_port = NULL;
    char    *cfg_path = NULL;

    signal(SIGINT, exit_sys);
    signal(SIGTERM, exit_sys);
    signal(SIGPIPE, sig_pipe);
    signal(SIGSEGV, sig_segv);

    openlog("mtp-portmap", LOG_CONS|LOG_PID|LOG_PERROR, LOG_USER);

	while ((opt = getopt(argc, argv, "df:p:v")) != -1) {
		switch (opt) {
			case 'd':
				daemon = false;
				break;
            case 'f':
                cfg_path = optarg;
                break;
			case 'p':
				ferry_port = optarg;
				break;
			case 'v':
				printf("%s\n", MTP_VERSION_STR);
				return 0;
			default:
				printf("Usage: %s [-d] | [-p port]\n", argv[0]);
				return 0;
		}
	}

	if (daemon && (create_daemon() != 0))
		return 0;

    if (__load_general_config() < 0)
        goto _end;
	if (ferry_port != NULL)
		__gg.ferry_port = atoi(ferry_port);

    memset(&__ut, 0x00, sizeof(__ut));

    __ut.vphttp.session_tout = TIMEOUT;

    if (load_portmap_cfg(&__ut, cfg_path) == -1)
        goto _end;

    while (1) {
        sleep(5);
    }
_end:
    exit_sys(DO_EXIT);
    return 0;
}

