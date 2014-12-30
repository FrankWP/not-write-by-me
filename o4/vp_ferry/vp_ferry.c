//#include "../vpheader.h"
#include "pm_proxy.h"

//#define  TOUT_SESSION  180

const static int  DEFAULT_TOUT = 180;
const static char LARG_GENERAL_PATH[] = "general_path";
const static char LARG_APP_PATH[] = "app_path";
const static char LARG_TOUT[] = "timeout";

const char *g_general_path = GENERAL_CONFIG_FILE;
static int g_tout = DEFAULT_TOUT;

static void quit_system(int sign)
{
    closelog();
    pm_quit();
    exit(sign);
}

/*
static void sig_segv(int signum)
{
    syslog(LOG_ERR, "Invalied memory operation.");
    pm_quit();
    _exit(-1);
}

static void sig_pipe(int signum)
{
    syslog(LOG_ERR, "Pipe broken.");
    pm_quit();
    _exit(-2);
}
*/

void run_ut_proxy(int proxy_type, int tout, bool daemon, bool cache, const char *manufactery, const char *parg)
{
    pvp_uthtrans ptu = NULL;
    struct pm_proxy pm;

    memset(&pm, 0x00, sizeof(struct pm_proxy));

    pm.pm_id = 0;
    pm.lip = __gg.local_priv_addr;
    pm.lport = __gg.ferry_port;

    pm.proxy_type = proxy_type;
    pm.time_out = tout;
    pm.manu = (char*)manufactery;
    //pm.head_type = E_NORMAL;

    if (/*cache */ (manufactery != NULL) && !pm_init(&pm, parg))
        return ;

    if (oss_malloc(&ptu, sizeof(vp_uthtrans)) < 0)
        return ;

    //ptu->vphttp.head_type = pm.head_type;
    ptu->vphttp.lip = pm.lip;
    ptu->vphttp.lport = pm.lport;
    //ptu->vphttp.dip = 0;
    //ptu->vphttp.dport = 0;
    ptu->vphttp.session_tout = pm.time_out;
    ptu->vphttp.data_cache = cache;
    ptu->vphttp.changeable = 0;

    ptu->do_socket = pm.do_socket;
    ptu->do_recv = pm.do_recv;
    ptu->do_request = pm.do_request;
    ptu->do_reply = pm.do_reply;
    ptu->do_close = pm.do_close;

    if (proxy_type == P_TCP_PROXY)
    {
        load_ferry_tcp_proxy(ptu, T_WAITING);
    }
    else
    {
        load_ferry_udp_proxy(ptu, T_WAITING);
    }
}

void Usage(const char *app_name)
{
    if (app_name != NULL)
	    printf("Usage: %s -t | -u | [-c ] [-m manufactery] | [-a initarg]\n", app_name);
}

bool parse_longarg(const char *name, const char *pArg)
{
    if ((name == NULL) || (pArg == NULL))
    {
        logwar_out("parse_longarg: argument error!");
        return false;
    }

	bool bRes = true;
	if (strcmp(name, LARG_GENERAL_PATH) == 0)
	{
        g_general_path = pArg;
	}
    else if (strcmp(name, LARG_APP_PATH) == 0)
    {
        set_app_dir(pArg);
    }
    else if (strcmp(name, LARG_TOUT) == 0)
    {
        g_tout = atoi(pArg);
    }
	else
		bRes = false;
	return bRes;
}

int main(int argc, char * argv[])
{
	int opt = -1;
	int optIdx = -1;
	int p_type = -1;
	bool daemon = true;
	bool cache = false;
    bool bRes = true;
	char *manu = NULL;
	char *parg = NULL; // for init function
	char *ferry_port = NULL;

    typedef enum _E_OPTS_GROUP
    {
        EOG_LONGARG = 1,
    }E_OPTS_GROUP;

	struct option opts[] = 
	{
		{ "cache", no_argument, NULL, 'c'},
		{ "debug", no_argument, NULL, 'd'},
		{ "tcp", no_argument, NULL, 't'},
		{ "udp", no_argument, NULL, 'u'},
		{ "version", no_argument, NULL, 'v'},

		{ "argument", required_argument, NULL, 'a'},
		{ "manufactory", required_argument, NULL, 'm'},
		{ "port_listen", required_argument, NULL, 'p'},
		{ LARG_GENERAL_PATH, required_argument, NULL, EOG_LONGARG},
        { LARG_APP_PATH, required_argument, NULL, EOG_LONGARG},
        { LARG_TOUT, required_argument, NULL, EOG_LONGARG},

		{0,0,0,0}
	};

	while ((opt = getopt_long(argc, argv, "\1:a:cdm:p:tuv", opts, &optIdx)) != -1) {
		switch (opt) {
            case EOG_LONGARG:
                bRes = parse_longarg(opts[optIdx].name, optarg);
                //general_path = optarg;
                break;
            //////////////////////////////
			case 'a':
				parg = optarg;
				break;
			case 'c':
				cache = true;
				break;
			case 'd':
				daemon = false;
				break;
			case 'm':
				manu = optarg;
				break ;
			case 'p':
				ferry_port = optarg;
				break;
			case 't':
				p_type = P_TCP_PROXY;
				break;
			case 'u':
				p_type = P_UDP_PROXY;
				break ;
			case 'v':
				printf("%s\n", MTP_VERSION_STR);
				return 0;
			default:
                Usage(argv[0]);
				return 0;
		}
        if ( ! bRes)
            break;
	}

    if ( ! bRes)
    {
        Usage(argv[0]);
		return 0;
    }

	if (p_type < 0 || p_type > 1) {
        Usage(argv[0]);
		return 0;
	}

	if (daemon && (create_daemon() != 0))
		return 0;

    pf_init_home();

	signal(SIGINT, quit_system);
	signal(SIGTERM, quit_system);
    //signal(SIGPIPE, sig_pipe);
    //signal(SIGSEGV, sig_segv);

	openlog("vp-ferry", LOG_CONS|LOG_PID|LOG_PERROR, LOG_USER);

	if (__load_general_config_path(g_general_path) < 0)
		return -1;
	if (ferry_port != NULL)
		__gg.ferry_port = atoi(ferry_port);

	run_ut_proxy(p_type, g_tout, daemon, cache, manu, parg);

	quit_system(DO_EXIT);
	return 0;
}

