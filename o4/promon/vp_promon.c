#include "../vpheader.h"

#define  TIME_SPEC  5
#define  PATH_CFG  "/topconf/topvp"
#define  PATH_EXEC "/tmp"

const static char L_PATH[] = "/home/log.txt";

void do_promon(char *line)
{
	FILE *pf = NULL;
	char path[128] = {0};
	char cmd[256] = {0};
    char line_for_cmd[256] = {0};
	char num_find[8] = {0};
	pid_t pid = -1;
    int  len_line = 0;
    
    if (line == NULL)
        return;
    len_line = strlen(line);
    if (len_line <= 0)
        return;

    strcpy(line_for_cmd, line);
    if (line_for_cmd[len_line - 1] == '&')
        line_for_cmd[len_line - 1] = '\0';
	trimright(line_for_cmd);

	pid = getpid();
	sprintf(path, "%s/.%d", PATH_EXEC, pid);
	sprintf(cmd, "ps -ef | grep '%s' | grep -v grep | wc -l > %s", line_for_cmd, path);
    //wlog(L_PATH, cmd);
    //wlog(L_PATH, line);

	for (;;)
	{
        system(cmd); 
		memset(num_find, 0x00, sizeof(num_find));
		if ((pf = fopen(path, "r")) == NULL)
		{
			logdbg_fmt("open info file %s failed!", path);
			continue;
		}
		fread(num_find, 1, sizeof(num_find), pf);
		fclose(pf);

		if ((num_find[0] == '\0') || 
			(atoi(num_find) == 0))
			system(line);

        sleep(TIME_SPEC);
	}
}

int main(int argc, char **argv)
{
	const static char annotate = '#';
	char *ptr_annotate = NULL;
    char    path[128] = {0};
	char	line[128] = {0};
	char	*buf = NULL;
	char	*ptr = NULL;
    size_t  buf_sz = 0;
	pid_t	pid = -1;
//    int     len = 0;

	if ((argc == 0) && (strcmp(argv[1], "-d") != 0))
	{
		if ((pid = create_daemon()) < 0)
			_exit(-1);
		else if (pid > 0)
			_exit(1);
	}

    openlog("vp-promon", LOG_CONS|LOG_PID|LOG_PERROR, LOG_USER);

    sprintf(path, "%s/promon.conf", PATH_CFG);

	if ( ! t_read_full_file(path, &buf, &buf_sz, 0))
	{
		logdbg_fmt("Open configure file failed!(%s)\n", path);
		return -1;
	}

	ptr = buf;
	while ((ptr = loop_line_from_buf(ptr, line, sizeof(line))) != NULL)
	{
		if ((ptr_annotate = strchr(line, annotate)) != NULL)
			*ptr_annotate = '\0';
		trimleft(line);
        /*
        if (line[strlen(line)-1] == '&')
            line[strlen(line)] = '\0';
            */

		if (line[0] == '\0')
			continue ;

		if ((pid = create_daemon()) < 0)
			break;
		else if (pid == 0)
			do_promon(line);	
	}
	oss_free(&buf);

	return 0;
}

