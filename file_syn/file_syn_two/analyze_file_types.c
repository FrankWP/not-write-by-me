#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<errno.h>
#include<linux/limits.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<dirent.h>

//所有函数的声明
typedef int MyFunc(const char *, const struct stat*, int);
static MyFunc myfunc;        //定义处理文件的函数
static int myftw(const char *,MyFunc *);
static int dopath(MyFunc *);

//定义的全局变量
static char *fullpath;    //存放文件的名称的变量
static long sock_c,lnk_c,reg_c,blk_c,dir_c,chr_c,fifo_c,total_c;    //统计各种文件类型的数量

//myfunc函数中需要定义的宏
#define FTW_F 1        //文件类型是文件
#define FTW_D 2        //文件类型是目录
#define FTW_NS 3    //一个文件不能stat
#define FTW_ND 4    //一个目录不能被读

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


	//使目录文件++
	if(0 != (ret=pmyfunc(fullpath,&statbuf,FTW_D)))
		return ret;

	//如果是目录文件则进入这个目录
	if(-1 == chdir(fullpath))
	{
		printf("%s[chdir]%s\n",fullpath,strerror(errno));
		ret == -1;
		return ret;
	}

	//打开当前目录
	if(NULL == (dp=opendir(".")))
	{
		ret = pmyfunc(fullpath,&statbuf,FTW_ND);
		return ret;
	}
	while(NULL != (dirp=readdir(dp)))
	{
		//忽略.和..文件(dot)
		if(0==strcmp(dirp->d_name,".") || 0==strcmp(dirp->d_name,".."))
			continue;
		memset(fullpath,0,PATH_MAX);
		strcpy(fullpath,dirp->d_name);

		if(0 != (ret=dopath(myfunc)))    //进行递归
			break;
	}
	chdir("..");    //将当前目录设置为上一级目录
	//对关闭文件进行判断
	if(-1 == closedir(dp))
	{
		printf("不能关闭%s\nError:%s",fullpath,strerror(errno));
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
								 printf("Error:这里不应该出现目录文件%s!\n\nError:%s\n",pathname,strerror(errno));
								 break;
			}
			break;
		case FTW_D:
			dir_c++;    break;
		case FTW_ND:
			printf("不能打开目录%s\nError:%s\n",pathname,strerror(errno));
			break;
		case FTW_NS:
			printf("不能打开文件%s\nError:%s\n",pathname,strerror(errno));
			break;
	}
	return 0;
}
