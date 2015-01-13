#include<netinet/in.h>              
#include<sys/types.h>              
#include<sys/socket.h>            
#include<stdio.h>               
#include<stdlib.h>             
#include<string.h>            
#include <unistd.h>
#include <stdarg.h>
#include <getopt.h>
#include <errno.h>
#include <syslog.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>
#include <dlfcn.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>


#define MAXFILE 65535

int create_daemon()  
{  
    int i ;  
    setsid();  
    chdir("/");  
    umask(0);  
    for(i = 0 ;i < MAXFILE ; i++){  
        close (i);  
    }  
  
}  
  
int main(int argc , char **argv)  
{  
    pid_t child1,child2;  
  
    child1 = fork();  
    if(child1 < 0 )  
        perror("fork error");  
      
    else if(child1 > 0)  
        exit(1);  
      
    create_daemon();   
  
    child2 = fork();  
    if(child2 < 0)  
        perror("fork error");  
      
    else if(child2 == 0){  
        syslog(LOG_INFO,"child2 will sleep for 10s");  
        sleep(10);  
  
        syslog(LOG_INFO , "child2 will exit");  
        exit(0);  
    }  
    else{  
        waitpid(child2,NULL,0);  
        syslog(LOG_INFO,"child1 noticed that child2 has exited");  
  
        closelog();  
  
        while(1){  
            sleep(10);  
        }  
    }  
    return 0;  
}  
