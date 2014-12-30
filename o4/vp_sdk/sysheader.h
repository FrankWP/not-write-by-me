#ifndef	__SYSHEADER_H_
#define	__SYSHEADER_H_

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
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
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>

#include "zlib.h"

#endif	//__SYSHEADER_H_

