#include "../vpheader.h"
//#include "mod_arg.h"

//static int   g_pmid = 0;
static char  g_pmid_str[64] = {0};
static int   g_ferry_port = 30020;
static char  g_ferry_port_str[] = "30020";
static char  g_cfgpath_portmap[128] = {0};
static void  (*doexit_sys)(int) = NULL;
//static void  (*exit_sys)(int) = NULL;

// signal call back
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

////////////////////////////////////////////////////:w
//
static void show_usage(char *app_name)
{
	printf("Usage: %s -i platform_id [-d] [-p ferry_port] [-v]\n", app_name);
}

bool a_init(int argc, char *argv[], void(*exit_sys)(int), const char *logname)
{
    int opt = -1;
	int optIdx = 0;
    bool is_daemon = true;
	char optStr[512] = {0};

	enum eOptGroup
	{
		EOG_MINIDX	= 1,
		EOG_NOARG	= 1,

        /*
		EOG_VERSION,
		EOG_DEBUG,
		EOG_ID,
		EOG_PORT,
        */
		EOG_APPPATH,
		EOG_CFGPATH_PORTMAP,

		EOG_MAXIDX
	};

	struct option opts[] = 
	{
		//{ "version", no_argument, NULL, EOG_VERSION },
		//{ "debug", no_argument, NULL, EOG_DEBUG },
		{ "version", no_argument, NULL, 'v' },
		{ "debug", no_argument, NULL, 'd' },

		//{ "id", required_argument, NULL, EOG_ID },
		//{ "port", required_argument, NULL, EOG_PORT },
		{ "id", required_argument, NULL, 'i' },
		{ "port", required_argument, NULL, 'p' },
		{ "apppath", required_argument, NULL, EOG_APPPATH},
		{ "cfgpath_portmap", required_argument, NULL, EOG_CFGPATH_PORTMAP },

		{0,0,0,0}
	};

    if (logname != NULL)
        openlog(logname, LOG_CONS|LOG_PID|LOG_PERROR, LOG_USER);
    /*
	optStr[0] = '\\';
	optStr[1] = EOG_NOARG;
	for (int i = EOG_MINIDX; i < EOG_MAXIDX; ++i)
	{
		optStr[(i * 3 - 1)] = '\\';
		optStr[(i * 3 - 1) + 1] = '0' + i;
		optStr[(i * 3 - 1) + 2] = ':';
	}
    */

	// load configures
    if (__load_general_config() < 0)
	{
		puts("读取常规配置文件失败!");
        closelog();
        return false;
	}

	sprintf(optStr, "%s\\x%x\\x%x", "di:p:v", EOG_CFGPATH_PORTMAP, EOG_APPPATH);
	//while ((opt = getopt_long(argc, argv, "di:p:v", opts, &optIdx)) != -1)
	while ((opt = getopt_long(argc, argv, optStr, opts, &optIdx)) != -1)
    {
		switch (opt) {
			case 'd':   // debug mode
				is_daemon = false;
				break;
            case 'i':
                //g_pmid = atoi(optarg);
                strcpy(g_pmid_str, optarg);
                break;
			case 'p':   // ferry port
				__gg.ferry_port = g_ferry_port = atoi(optarg);
                // not copy string is for safe and unanimous
                sprintf(g_ferry_port_str, "%d", g_ferry_port); 
				break;
			case 'v':   // show version
				printf("%s\n", MTP_VERSION_STR);
                exit(0);
            case EOG_CFGPATH_PORTMAP:
                strcpy(g_cfgpath_portmap, optarg);
                break;
            case EOG_APPPATH:
                set_app_dir(optarg);
                break;
			default:
                show_usage(argv[0]);
				return false;
		}
	}
    //if (g_pmid == 0)
    if (g_pmid_str[0] == 0)
    {
        show_usage(argv[0]);
        closelog();
        return false;
    }
    if (is_daemon)
    {
        if ((create_daemon() != 0))
        {
            closelog();
            return false;
        }
    }

    if (set_limit() < 0)
    {
        closelog();
        return false;
    }

    // register signal
    if (exit_sys != NULL)
    {
        doexit_sys = exit_sys;
        signal(SIGINT, exit_sys);
        signal(SIGTERM, exit_sys);
    }
    if (is_daemon)
    {
        signal(SIGPIPE, sig_pipe);
        signal(SIGSEGV, sig_segv);
    }

    return true;
}

void a_exit(int n)
{
    closelog();
/* exit_sys always is null
    if (exit_sys != NULL)
        exit_sys(n);
*/
    if (doexit_sys != NULL)
        doexit_sys(n);
    exit(n);
}

int  a_get_pmid()
{
    //return g_pmid;
    return atoi(g_pmid_str);
}

char *a_get_pmid_str()
{
    return g_pmid_str;
}

int  a_get_ferry_port()
{
    return g_ferry_port;
}

char *a_get_ferry_port_str()
{
    return g_ferry_port_str; 
}

char *a_get_cfgpath_portmap()
{
    return g_cfgpath_portmap;
}

