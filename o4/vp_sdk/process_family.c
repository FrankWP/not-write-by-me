#include "common.h"
#include "process_family.h"

#define SIG_DISMISS_MEMBER	(SIGRTMIN + 1)
#define SIG_AWAY_FAMILY		(SIGRTMIN + 2)
    
pthread_mutex_t pf_mutex;

typedef struct __pf_process_id
{
	pid_t pid;
	struct __pf_process_id *next;
}pf_pro_id;

typedef struct __pf_home
{
	int token;
	pf_pro_id *pro_id;
}pf_home;

typedef struct __pf_member
{
	pid_t home_pid;
	int token;
	int exit_code;
	void (*before_exit)(int);
}pf_member;

static pf_home g_pf_home = {token:-1, pro_id:NULL};
static pf_member g_pf_member = {home_pid:0, token:-1, exit_code:0, before_exit:NULL};

static void home_signal_handler(int signum, siginfo_t *info, void *myact);
static void member_signal_handler(int signum, siginfo_t *info, void *myact);
static bool pf_add_pro_id(pf_pro_id **ppro_id, pid_t pid);
static bool pf_del_pro_id(pf_pro_id **ppro_id, pid_t pid);
static bool pf_del_member(pid_t member_pid);

static void home_signal_handler(int signum, siginfo_t *info, void *myact)
{
	if (info->si_signo != SIG_AWAY_FAMILY)
    {
        if (info->si_signo == SIGTERM)
        {
            pf_destroy_home();
            exit(0);
        }
		return;
    }
	//printf("%d away from home %d", info->si_value.sival_int, getpid());
	pf_del_member(info->si_value.sival_int);
}

static void member_signal_handler(int signum, siginfo_t *info, void *myact)
{
	// signal must be sending from home process.
	if (info->si_pid != g_pf_member.home_pid)
		return;

	if (info->si_signo == SIG_DISMISS_MEMBER)
	{
		if (info->si_value.sival_int == g_pf_member.token)
		{
			// member of family exits process.
			if (g_pf_member.before_exit != NULL)
				g_pf_member.before_exit(PF_DISMISSED);
				//g_pf_member.before_exit(g_pf_member.exit_code);

			exit(g_pf_member.exit_code);
		}
	}
}

////////////
// functions
//
static bool
pf_add_pro_id(pf_pro_id **ppro_id, pid_t pid)
{
	pf_pro_id *pro_id = NULL; 

	if (ppro_id == NULL)
		return false;

	if ((pro_id = (pf_pro_id*)malloc(sizeof(pf_pro_id))) == NULL)
		return false;

	memset(pro_id, 0, sizeof(pf_pro_id));
	pro_id->pid = pid;

pthread_mutex_lock(&pf_mutex);
	pro_id->next = *ppro_id;
	*ppro_id = pro_id;
pthread_mutex_unlock(&pf_mutex);

	return true;;
}

static bool
pf_del_pro_id(pf_pro_id **ppro_id, pid_t pid)
{
	pf_pro_id *pro_id = NULL; 
	pf_pro_id *pro_id_tmp = NULL; 

	if (ppro_id == NULL || *ppro_id == NULL)
		return false;

pthread_mutex_lock(&pf_mutex);
	pro_id = *ppro_id;
	while (pro_id != NULL)
	{
		if (pro_id->pid == pid)
		{
			if (pro_id_tmp != NULL)
				pro_id_tmp->next = pro_id->next;
			else
				*ppro_id = pro_id->next;

			free(pro_id);
			pro_id = NULL;
			break;
		}
		pro_id_tmp = pro_id;
		pro_id = pro_id->next;
	}
pthread_mutex_unlock(&pf_mutex);
	
	return (pro_id != pro_id_tmp);
}

static bool pf_del_member(pid_t member_pid)
{
	return pf_del_pro_id(&g_pf_home.pro_id, member_pid);
}

/*
 * functions about process family's home side.
 */
bool
pf_init_home()
{
	struct sigaction act;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_SIGINFO;
    act.sa_sigaction = home_signal_handler;

	pthread_mutex_init(&pf_mutex, NULL);

    if (sigaction(SIG_AWAY_FAMILY, &act, NULL) < 0)
	{
        loginf_out("process_family: pf_init_home install signal error.");
		return false;
	}
	return true;
}

bool pf_add_member(pid_t member_pid)
{
	//loginf_fmt("%d add to home %d", member_pid, getpid());
	return pf_add_pro_id(&g_pf_home.pro_id, member_pid);
}

void pf_dismiss_member(pid_t member_pid)
{
	pf_pro_id *pro_id = NULL;
	pf_pro_id *pro_id_tmp = NULL;
	sigval_t sigvar;

pthread_mutex_lock(&pf_mutex);
	pro_id = g_pf_home.pro_id;
    if (pro_id->pid == member_pid)
    {
        g_pf_home.pro_id = g_pf_home.pro_id->next;

		sigvar.sival_int = pro_id->pid;
        sigqueue(pro_id->pid, SIG_DISMISS_MEMBER, sigvar);
		free(pro_id);
    }
    else
    {
        pro_id_tmp = pro_id;
        pro_id = pro_id->next;
        while (pro_id != NULL)
        {
            if (pro_id->pid == member_pid)
            {
                printf("process_family: dismiss_member pid[%d]\n", member_pid);
                pro_id_tmp->next = pro_id->next;

                sigvar.sival_int = pro_id->pid;
                sigqueue(pro_id->pid, SIG_DISMISS_MEMBER, sigvar);
                free(pro_id);
                break;
            }
            pro_id_tmp = pro_id;
            pro_id = pro_id->next;
        }
	}
pthread_mutex_unlock(&pf_mutex);
}

void pf_destroy_home()
{
	pf_pro_id *pro_id = NULL;
	pf_pro_id *pro_id_tmp = NULL;
	sigval_t sigvar;

pthread_mutex_lock(&pf_mutex);
	pro_id = g_pf_home.pro_id;
	while (pro_id != NULL)
	{
		pro_id_tmp = pro_id;
		pro_id = pro_id->next;

		sigvar.sival_int = pro_id_tmp->pid;
        sigqueue(pro_id_tmp->pid, SIG_DISMISS_MEMBER, sigvar);
		free(pro_id_tmp);
	}
	g_pf_home.pro_id = NULL;
	g_pf_home.token = -1;
pthread_mutex_unlock(&pf_mutex);

}

/*
 * functions about process family's member side.
 */
bool
pf_init_member(void (*before_exit)(int), int exit_code)
{
	struct sigaction act;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_SIGINFO;
    act.sa_sigaction = member_signal_handler;

	g_pf_member.home_pid = getppid();
	g_pf_member.token = getpid();
	g_pf_member.exit_code = exit_code;
	g_pf_member.before_exit = before_exit;

    if (sigaction(SIG_DISMISS_MEMBER, &act, NULL) < 0)
	{
        //loginf_out("process_family: pf_init_member install signal error.");
		return false;
	}

	return true;
}

void
pf_away_home()
{
	sigval_t sigvar;
	if (g_pf_member.home_pid == 0)
		return;

	sigvar.sival_int = getpid();
	sigqueue(g_pf_member.home_pid, SIG_AWAY_FAMILY, sigvar);
}

pid_t
pf_daemon()
{
	return create_daemon();
}

