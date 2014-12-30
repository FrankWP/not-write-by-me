#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<errno.h>
#include<linux/limits.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<dirent.h>

//���к���������
typedef int MyFunc(const char *, const struct stat*, int);
static MyFunc myfunc;        //���崦���ļ��ĺ���
static int myftw(const char *,MyFunc *);
static int dopath(MyFunc *);

//�����ȫ�ֱ���
static char *fullpath;    //����ļ������Ƶı���
static long sock_c,lnk_c,reg_c,blk_c,dir_c,chr_c,fifo_c,total_c;    //ͳ�Ƹ����ļ����͵�����

//myfunc��������Ҫ����ĺ�
#define FTW_F 1        //�ļ��������ļ�
#define FTW_D 2        //�ļ�������Ŀ¼
#define FTW_NS 3    //һ���ļ�����stat
#define FTW_ND 4    //һ��Ŀ¼���ܱ���

int main(int argc,char *argv[])
{
	if(argc != 2)
	{
		printf("Usage:%s pathname\n",argv[0]+2);
		exit(EXIT_FAILURE);
	}

	myftw(argv[1],myfunc);
	total_c = sock_c+lnk_c+reg_c+blk_c+dir_c+chr_c+fifo_c;
	if(0 == total_c)
	{
		total_c = 1;
	}
	printf("socket files    = %7ld, %5.2f%%\n",sock_c,sock_c*100.0/total_c);
	printf("link files      = %7ld, %5.2f%%\n",lnk_c,lnk_c*100.0/total_c);
	printf("regular files   = %7ld, %5.2f%%\n",reg_c,reg_c*100.0/total_c);
	printf("block files     = %7ld, %5.2f%%\n",blk_c,blk_c*100.0/total_c);
	printf("directory files = %7ld, %5.2f%%\n",dir_c,dir_c*100.0/total_c);
	printf("character files = %7ld, %5.2f%%\n",chr_c,chr_c*100.0/total_c);
	printf("FIFO files      = %7ld, %5.2f%%\n",fifo_c,fifo_c*100.0/total_c);
	printf("total files     = %7ld, %5.2f%%\n",total_c,total_c*100.0/total_c);

	return 0;
}

static int myftw(const char* pathname, MyFunc *pmyfunc)
{
	int ret;

	fullpath = (char *)malloc(sizeof(char)*PATH_MAX);
	strcpy(fullpath,pathname);
	//puts("HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH start");
	ret = dopath(myfunc);
	//puts("HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH end");
	free(fullpath);

	return ret;
}

static int dopath(MyFunc *pmyfunc)
{
	int ret;
	struct stat statbuf;
	char *ptr;
	DIR *dp;
	struct dirent* dirp;

	printf("now full path is:%s\n", fullpath);

	if(-1 == lstat(fullpath,&statbuf))
	{
		ret = pmyfunc(fullpath,&statbuf,FTW_NS);
		return ret;
	}

	puts("");
	puts("BBBB before is file");
	if(S_ISDIR(statbuf.st_mode) != 1)
	{
		ret = pmyfunc(fullpath,&statbuf,FTW_F);
		printf("---- file:%s\n", fullpath);
		return ret;
	}
	puts("AAAA after is file");
	puts("");


	//ʹĿ¼�ļ�++
	if(0 != (ret=pmyfunc(fullpath,&statbuf,FTW_D)))
		return ret;

	//�����Ŀ¼�ļ���������Ŀ¼
	if(-1 == chdir(fullpath))
	{
		printf("%s[chdir]%s\n",fullpath,strerror(errno));
		ret == -1;
		return ret;
	}

	//�򿪵�ǰĿ¼
	if(NULL == (dp=opendir(".")))
	{
		ret = pmyfunc(fullpath,&statbuf,FTW_ND);
		return ret;
	}
	while(NULL != (dirp=readdir(dp)))
	{
		//����.��..�ļ�(dot)
		if(0==strcmp(dirp->d_name,".") || 0==strcmp(dirp->d_name,".."))
			continue;
		memset(fullpath,0,PATH_MAX);
		strcpy(fullpath,dirp->d_name);

		if(0 != (ret=dopath(myfunc)))    //���еݹ�
			break;
	}
	chdir("..");    //����ǰĿ¼����Ϊ��һ��Ŀ¼
	//�Թر��ļ������ж�
	if(-1 == closedir(dp))
	{
		printf("���ܹر�%s\nError:%s",fullpath,strerror(errno));
	}

	return ret;
}

static int myfunc(const char * pathname,const struct stat * statptr,int type)
{
	switch(type)
	{
		case FTW_F:
			switch(statptr->st_mode & S_IFMT)
			{
				case S_IFSOCK:    sock_c++;    break;
				case S_IFLNK:    lnk_c++;    break;
				case S_IFREG:    reg_c++;    break;
				case S_IFBLK:    blk_c++;    break;
				case S_IFCHR:    chr_c++;    break;
				case S_IFIFO:    fifo_c++;    break;
				case S_IFDIR:
								 printf("Error:���ﲻӦ�ó���Ŀ¼�ļ�%s!\n\nError:%s\n",pathname,strerror(errno));
								 break;
			}
			break;
		case FTW_D:
			dir_c++;    break;
		case FTW_ND:
			printf("���ܴ�Ŀ¼%s\nError:%s\n",pathname,strerror(errno));
			break;
		case FTW_NS:
			printf("���ܴ��ļ�%s\nError:%s\n",pathname,strerror(errno));
			break;
	}
	return 0;
}
