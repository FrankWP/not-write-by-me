#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv)
{
	FILE *stream;
	char cmd[256] = {0};
	char buf[1024] = {0};

	char src[16] = "src";
	char dst[16] = "dst";	

	sprintf(cmd, "mv %s %s", src, dst);
	//sprintf(cmd, "ls -l");
	stream = popen(cmd, "r");
	if (stream == NULL)
	{
		printf("stream is null\n");
		return -1;
	}
	int num = fread(buf, 1, sizeof(buf), stream);
	printf("%d\n", num);

	printf("%s\n", buf);	

	pclose(stream);

	return 0;
}
