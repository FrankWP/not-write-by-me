#
#
include ../config.mak

SDK_PATH	= ../vp_sdk
LIB_PATH	= $(SDK_PATH)
VPATH		= $(LIBPATH)

SDK_SRCS	= $(wildcard $(SDK_PATH)/*.c)
SDK_HEDS	= $(wildcard $(SDK_PATH)/*.h)
SDK_OBJS	= $(patsubst %.c, %.o, $(SDK_SRCS))

MOD_PATH	= ../vp_mod
MOD_SRCS	= $(wildcard $(MOD_PATH)/*.c)
MOD_OBJS	= $(patsubst %.c, %.o, $(MOD_SRCS))

HEADS		= $(wildcard *.h)
SRCS		= $(wildcard *.c)
OBJS		= $(patsubst %.c, %.o, $(SRCS))

LIBS     	= $(G_LIBS) -lpthread #-llicense -lssl #-lmysqlclient # -levent
WARN		= -Wall -Wcast-align -Wsign-compare -unreachable-code #-Wmissing-prototypes #-Wpacked -Wpadded -Winline #-Werror
CFLAGS		= $(G_CFLAGS)
LDFLAGS  	= -L$(LIB_PATH) -L/usr/lib/mysql $(LIBS) 
BINS		= sys-manager	\
			  sys-license	\
			  vp-flowsvr

all : $(BINS)

#sys-manager: $(SDK_HEDS) sys_manager.c $(SDK_SRCS)
#	$(CC) -o $@ $(patsubst $(SDK_HEDS), ,$^) $(CFLAGS) $(LDFLAGS) 
sys-manager: $(SDK_HEDS) sys_manager.c $(SDK_OBJS)
	$(CC) -o $@ $(patsubst $(SDK_HEDS), ,$^) $(CFLAGS) $(LDFLAGS) 

#sys-license: $(SDK_HEDS) sys_license.c $(SDK_SRCS)
#	$(CC) -o $@ $(patsubst $(SDK_HEDS), ,$^) $(CFLAGS) $(LDFLAGS) 
sys-license: $(SDK_HEDS) sys_license.c $(SDK_OBJS)
	$(CC) -o $@ $(patsubst $(SDK_HEDS), ,$^) $(CFLAGS) $(LDFLAGS) 

#vp-flowsvr: $(SDK_HEDS) vp_flowsvr.c $(SDK_SRCS) $(MOD_SRCS)
#	$(CC) -o $@ $(patsubst $(SDK_HEDS), ,$^) $(CFLAGS) $(LDFLAGS) -lmysqlclient 
vp-flowsvr: $(SDK_HEDS) vp_flowsvr.c $(SDK_OBJS) $(MOD_OBJS)
	$(CC) -o $@ $(patsubst $(SDK_HEDS), ,$^) $(CFLAGS) $(LDFLAGS) -lmysqlclient 

clean:
	$(RM) *.o $(BINS)

