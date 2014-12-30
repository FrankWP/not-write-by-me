#include "../vpheader.h"
#include "mod_tools.h"

/*
static void print_char(char ch);
static void dis_interpret(const unsigned char *buf, int len);

static void
print_char(char ch)
{
	if(isprint(ch))
		fputc(ch, stdout);
	else
		fputc('.', stdout);
}

static void dis_interpret(const unsigned char *buf, int len)
{
	printf("\t");
	int idx = 0;
	while (idx < len)
		print_char(buf[idx++]);
	printf("\n");
}

void t_disbuf(const unsigned char *buf, int len)
{
	int idx = 0;
	int len_tail = len % 16;
	const unsigned char *tail = buf + (len / 16) * 16;

	while(idx + 16 <= len)
	{
		printf("%04x  ", idx);
		printf("%02x %02x %02x %02x %02x %02x %02x %02x - %02x %02x %02x %02x %02x %02x %02x %02x ",
				buf[idx], buf[idx+1], buf[idx+2], buf[idx+3], buf[idx+4], buf[idx+5], buf[idx+6], buf[idx+7],
				buf[idx+8], buf[idx+9], buf[idx+10], buf[idx+11], buf[idx+12], buf[idx+13], buf[idx+14], buf[idx+15]);
		dis_interpret(buf + idx, 16);
		idx += 16;
	}

	if (idx < len - 1)
	{
		printf("%04x  ", idx);
		idx = 0;
		while (idx < 16)
		{
			if (idx == 8)
				printf("- ");
			if (idx < len_tail)
				printf("%02x ", tail[idx]);
			else
				printf("** ");

			++idx;
		}
		dis_interpret(tail, len_tail);
	}
}
*/

size_t
t_getfilesz(FILE *f)
{
	if (f == NULL)
		return 0;

	struct stat fs;
	fstat(f->_fileno, &fs);

	return fs.st_size;
}

bool
t_read_full_file_by_stream(FILE *pf, char **buf, size_t *sz_buf, size_t sz_limit)
{
	if ( (pf == NULL) || (buf == NULL))
		return false;

	size_t filesz = t_getfilesz(pf);
	if ( (sz_limit != 0) && (filesz > sz_limit))
		return false;
	if (sz_buf != NULL)
		*sz_buf = 0;	// if any error occers size 0 will be passed to caller.
	if (filesz == 0)
		return true;

	*buf = (char*)malloc(filesz);
	if (*buf == NULL)
		return false;

	fseek(pf, 0L, SEEK_SET);
	long nread = fread(*buf, filesz, 1, pf);
	if ( nread != 1)
	{
		free(*buf);
		return false;
	}
	if (sz_buf != NULL)
		*sz_buf = filesz;

	return true;
}

bool
t_read_full_file(const char *fpath, char **buf, size_t *sz_buf, size_t sz_limit)
{
	if ((fpath == 0) || (buf == 0))
		return false;

	FILE *pf = NULL;
	bool res = false;
	if ((pf = fopen(fpath, "rb")) == NULL)
		return false;
	res = t_read_full_file_by_stream(pf, buf, sz_buf, sz_limit);
	fclose(pf);

	return res;
}

bool
t_backup_file(const char *fname, const char *info)
{
    static const char bak[] = "Bak";

	if (fname == NULL)
		return false;

    time_t  now = time(0);
    struct tm ltm;
    localtime_r(&now, &ltm);

    if (info == NULL)
        info = bak;
    char backup_name[512] = {0};
    sprintf(backup_name, "%s.%s.[%d-%d-%d.%d:%d:%d]", fname, info, 
                                ltm.tm_year + 1900, ltm.tm_mon, ltm.tm_mday, ltm.tm_hour, ltm.tm_min, ltm.tm_sec);
    if (rename(fname, backup_name) != 0)
    {
        return false;
    }

    return true;
}

char *
t_get_conf_line(char *buf, char *store)
{
	char *begPos = buf;
	char *retPos = NULL;
	char *pStrEnd = NULL;
	char *pLineEnd = NULL;
	int len = 0;
	bool has_comment = false;

	if ((buf == NULL) || (*buf == '\0') || (store == NULL))
		return NULL;

	for (pLineEnd = buf; *pLineEnd != '\0'; ++pLineEnd)
	{
		if (*pLineEnd == '#')
		{
			if (pLineEnd == begPos)
			{
				while (*pLineEnd != '\0')
				{
					if (*pLineEnd == '\n')
					{
						break;
					}
					else if ((*pLineEnd == '\r') && (*pLineEnd == '\n'))
					{
						++pLineEnd;
						break;
					}
					++pLineEnd;
				}
				begPos = pLineEnd + 1;
				continue;
			}
			else
			{
				pStrEnd = pLineEnd;
				has_comment = true;
			}
		}
		else if (*pLineEnd == '\n')
		{
			if (pLineEnd == begPos)
			{
				begPos = pLineEnd + 1;
				continue;
			}
			retPos = pLineEnd + 1;
			break;
		}
		else if ( (*pLineEnd == '\r') && (*(pLineEnd+1) == '\n'))
		{
			if (pLineEnd == begPos)
			{
				++pLineEnd;
				begPos = pLineEnd + 1;
				continue;
			}
			retPos = pLineEnd + 2;
			break;
		}
	}
	if ( ! has_comment)
		pStrEnd = pLineEnd;

	len = pStrEnd - begPos;
	if (len == 0)
		return NULL;
	memcpy(store, begPos, len);
	store[len] = '\0';

	return retPos;
}

