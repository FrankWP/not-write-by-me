
#include "syshead.h"
#include "md5.h"
#include "display.h"
#include "read_conf.h"

void setp(char **p)
{
	char *s = (char*)calloc(32, sizeof(char));
	memcpy(s, "12345", 6);
	*p = s;
}

int main( )
{
	char *p;
	setp(&p);
	printf("%s\n", p);
	free(p);

	return 0;
}


