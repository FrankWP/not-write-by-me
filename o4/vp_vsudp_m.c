#include "vpheader.h"

static int g_tout = 30;
static int g_lip = 0;
static int g_lport = 0;
static int g_dip = 0;
static int g_dport = 0;

const static char LARG_LIP[] = "lip";   // local ip address. 
const static char LARG_LPORT[] = "lport";   // local port. 
const static char LARG_DIP[] = "dip";   // dest ip address.
const static char LARG_DPORT[] = "dport";   // dest port.
const static char LARG_TOUT[] = "tout";   // timeout

//static void quit_system(int n)
//{
 //   exit(n);
//}

void show_usages(char *name)
{
    if (name == NULL)
        return ;
    printf("Usages: %s -p port -d --lip=LocalIp --lport=LocalPort --dip=DestIp --dport=DestPort --tout=timeout\n", name);
}

/////////////////////////////////////////////////////////
//
bool parse_longarg(const char *name, const char *pArg)
{
    if ((name == NULL) || (pArg == NULL))
    {
        //logwar_out("parse_longarg: argument error!");
        return false;
    }

	bool bRes = true;
	if (strcmp(name, LARG_LIP) == 0)    // local ip
	{
        g_lip = inet_atoul(pArg);
	}
    else if (strcmp(name, LARG_LPORT) == 0) // local port
    {
        g_lport = atoi(pArg);
    }
    else if (strcmp(name, LARG_DIP) == 0)   // dest ip
    {
        g_dip = inet_atoul(pArg);
    }
    else if (strcmp(name, LARG_DPORT) == 0) // dest port
    {
        g_dport = atoi(pArg);
    }
    else if (strcmp(name, LARG_TOUT) == 0)
    {
        g_tout = atoi(pArg);
    }
	else
		bRes = false;
	return bRes;
}


bool arg_init(int argc, char **argv)
{
    int opt = -1;
	int optIdx = 0;
    bool is_daemon = true;
	char optStr[512] = {0};
    int ferry_port = 0;

	enum eOptGroup
	{
		EOG_MINIDX	= 1,
		EOG_NOARG	= 1,

		EOG_LONGARG = 2,

		EOG_MAXIDX
	};

	struct option opts[] = 
	{
		{ "version", no_argument, NULL, 'v' },
		{ "debug", no_argument, NULL, 'd' },
		{ "port", required_argument, NULL, 'p' },

		{ LARG_LIP, required_argument, NULL, EOG_LONGARG},
		{ LARG_LPORT, required_argument, NULL, EOG_LONGARG},
		{ LARG_DIP, required_argument, NULL, EOG_LONGARG},
		{ LARG_DPORT, required_argument, NULL, EOG_LONGARG},
		{ LARG_TOUT , required_argument, NULL, EOG_LONGARG},

		{0,0,0,0}
	};

	sprintf(optStr, "%s\\x%x", "di:p:v", EOG_LONGARG);
	while ((opt = getopt_long(argc, argv, optStr, opts, &optIdx)) != -1)
    {
		switch (opt) {
			case 'd':   // debug mode
				is_daemon = false;
				break;
			case 'p':   // ferry port
				//__gg.ferry_port = atoi(optarg);
				ferry_port = atoi(optarg);
				break;
			case 'v':   // show version
				printf("%s\n", MTP_VERSION_STR);
                exit(0);
            case EOG_LONGARG:
                if ( ! parse_longarg(opts[optIdx].name, optarg))
                {
                    puts("parse long arg failed!");
                    exit(0);
                }
                break;
			default:
                show_usages(argv[0]);
				return false;
		}
	}

	// load configures
    if (__load_general_config() < 0)
	{
		puts("读取常规配置文件失败!");
        return false;
	}
    if (ferry_port != 0)
        __gg.ferry_port = ferry_port;

    if (is_daemon)
    {
        if ((create_daemon() != 0))
            return false;
    }

    // register signal
    //if (exit_sys != NULL)
    //{
        //signal(SIGINT, exit_sys);
        //signal(SIGTERM, exit_sys);
    //}
    //signal(SIGPIPE, sig_pipe);
    //signal(SIGSEGV, sig_segv);

    return true;
}

int main(int argc, char * argv[])
{
//    if (g_pport) {
        //u_pplist = create_pp_smem(PP_SMNAME);
        //g_vport = pvstream->lvport;
    //}
    if ( ! arg_init(argc, argv))
        return 0;
    load_udp_proxy_simple_n(T_WAITING, 0, g_tout,0,
            g_lip,g_lport, g_dip,g_dport,
            NULL,NULL,NULL,NULL,NULL);

    return 0;
}

