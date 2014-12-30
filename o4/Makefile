#
# Video Platform Project
#

include config.mak

WARS		= -Wall -Winvalid-pch #-unreachable-code #-Wimplicit-function-declaration 
LIBS     	= $(G_LIBS) -lpthread -lm -lmysqlclient #-llicense -lssl  #-levent
CFLAGS   	= $(G_CFLAGS)
LDFLAGS  	= -L$(LIB_PATH) $(LIBS) -L/usr/lib/mysql 

SDK_PATH	= vp_sdk
SDK_SRCS	= $(wildcard $(SDK_PATH)/*.c)
SDK_HEDS	= $(wildcard $(SDK_PATH)/*.h)
SDK_OBJS	= $(patsubst %.c, %.o, $(SDK_SRCS))

MOD_PATH	= vp_mod
MOD_SRCS	= $(wildcard $(MOD_PATH)/*.c)
MOD_OBJS	= $(patsubst %.c, %.o, $(MOD_SRCS))

SYS_PATH	= vp_sys
SYS_SRCS	= $(wildcard $(SYS_PATH)/*.c)
SYS_OBJS	= $(patsubst %.c, %.o, $(SYS_SRCS))

LIB_PATH	= $(SDK_PATH)
VPATH		= $(LIBPATH)

dirs := $(shell find . -maxdepth 1 -type d)
dirs := $(basename $(patsubst ./%,%,$(dirs)))
dirs := $(filter-out $(exclude_dirs),$(dirs))
dirs := $(patsubst $(SDK_PATH), , $(dirs))
dirs := $(patsubst $(MOD_PATH), , $(dirs))
dirs := $(patsubst ascript, , $(dirs))
dirs := $(patsubst license_tools, , $(dirs))
#dirs := $(patsubst vp_ferry, , $(dirs))

SUBDIRS := $(dirs)

PCH_PATH	= $(SDK_PATH)
PCH_H		= sysheader.h
PCH			= $(PCH_H).gch

VP_VSTCP	= vp-vstcp
VP_VSUDP	= vp-vsudp
VP_VSUDP_M	= vp-vsudp-m
VP_PORTMAP  = vp-portmap
BINS		= $(VP_VSTCP) $(VP_VSUDP) $(VP_PORTMAP) $(VP_VSUDP_M) t

define make_subdir
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && make $1) \
	done;
endef

default : $(BINS)

$(PCH) : $(PCH_PATH)/$(PCH_H)
	$(CC) $^ -o $@ $(CFLAGS)

$(VP_VSTCP): $(PCH) $(SDK_HEDS) $(SDK_OBJS) $(MOD_OBJS) vp_vstcp.c
	$(CC) -o $@ $(patsubst $(PCH) $(SDK_HEDS), , $^) $(CFLAGS) $(LDFLAGS) 

$(VP_VSUDP): $(PCH) $(SDK_HEDS) $(SDK_OBJS) vp_vsudp.c
	$(CC) -o $@ $(patsubst $(PCH) $(SDK_HEDS), , $^) $(CFLAGS) $(LDFLAGS) 

$(VP_PORTMAP): $(PCH) $(SDK_HEDS) $(SDK_OBJS) vp_portmap.c
	$(CC) -o $@ $(patsubst $(PCH) $(SDK_HEDS), , $^) $(CFLAGS) $(LDFLAGS)

$(VP_VSUDP_M): $(PCH) $(SDK_HEDS) $(SDK_OBJS) vp_vsudp_m.c
	$(CC) -o $@ $(patsubst $(PCH) $(SDK_HEDS), , $^) $(CFLAGS) $(LDFLAGS) 

t: $(PCH) $(SDK_HEDS) $(SDK_OBJS) $(MOD_OBJS) t.c
	$(CC) -o $@ $(patsubst $(PCH) $(SDK_HEDS), , $^) $(CFLAGS) $(LDFLAGS) 

all: $(BINS)
	$(call make_subdir, all)

.PHONY : clean cleanall

clean:
	$(RM) *.o $(BINS) $(PCH)

cleanall:
	$(RM) *.o $(BINS) $(PCH) cscope.* tags
	$(call make_subdir, clean)
	cd $(SDK_PATH) && make clean
	cd $(MOD_PATH) && make clean
