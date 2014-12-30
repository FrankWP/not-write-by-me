#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <time.h>

int main (void)
{
	FILE *pf = NULL ;
	char session[128] = {0};	
	sprintf(session, "./%s.html", "abc");
	char *dev = "dev";
	char *userName = "userName";
	int ram = 1;
	pf = fopen(session,"w");
	if (pf)
	{
		fprintf(pf,"<HTML>\n");
		fprintf(pf,"<frameset rows=\"90,*\" framespacing=0 frameborder=0 border=0 name=\"home\">");
		fprintf(pf,"<FRAME name=\"hmoeTile\" src=\"/home.html\" border=0 marginwidth=0 marginheight=0 scrolling=no noresize>");		
		if (dev)
		{
			fprintf(pf,"<FRAME name=\"worktop\" src=\"/cgi-bin/mainwork.cgi?userName=%s&testFileName=%s&sessid=%d\" border=0 marginwidth=0 marginheight=0 noresize>",userName,dev,ram);
		}
		else
		{
			fprintf(pf,"<FRAME name=\"worktop\" src=\"/cgi-bin/mainwork.cgi?userName=%s&sessid=%d\" border=0 marginwidth=0 marginheight=0 noresize>",userName,ram);
		}
		fprintf(pf,"</frameset>\n</html>\n"); 
		
		fclose(pf);
	}
	return 0;
}

