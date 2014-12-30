#
# Video Platform Project
#

include ../config.mak
include ../config.manu

LIBS     	= $(G_LIBS) -lrt -lpthread -lm -lz -lmysqlclient #-llicense -lssl #-levent
CFLAGS   	= $(G_CFLAGS)
LDFLAGS  	= -L$(LIB_PATH) -L/usr/lib/mysql $(LIBS) 

HEADS		= $(wildcard *.h)
SRCS		= $(wildcard *.c)
OBJS		= $(patsubst %.c, %.o, $(SRCS))

SYS_PATH	= ../vp_sys
SYS_SRCS	= $(wildcard $(SYS_PATH)/*.c)
SYS_OBJS	= $(patsubst %.c, %.o, $(SYS_SRCS))

LIB_PATH	= $(SDK_PATH)
VPATH		= $(LIBPATH)

PCH_PATH	= $(SDK_PATH)
PCH_H		= sysheader.h
PCH			= ../$(PCH_H).gch

VP_FERRY	= vp-ferry
BINS		= $(VP_FERRY)

.PHONY : clean 

all: $(BINS)

$(PCH) : $(PCH_PATH)/$(PCH_H)
	$(CC) $^ -o $@ $(CFLAGS)

$(VP_FERRY): $(PCH) $(SDK_HEDS) $(OBJS) $(SDK_OBJS) $(MOD_OBJS)
	$(CC) -o $@ $(patsubst $(PCH) $(SDK_HEDS), ,$^) $(CFLAGS) $(LDFLAGS) 

clean:
	$(RM) *.o $(BINS)

