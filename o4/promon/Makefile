#
#
include ../config.mak
include ../config.manu

LIBS     	= $(G_LIBS) -lpthread -lmysqlclient #-llicense -lssl # -levent
WARN		= -Wall -Winvalid-pch -unreachable-code -g #-Wcast-align -Wsign-compare #-Wmissing-prototypes -Wpacked -Wpadded -Winline #-Werror
CFLAGS		= $(G_CFLAGS)
LDFLAGS  	= -L$(LIB_PATH) -L/usr/lib/mysql $(LIBS)

BIN_PROMON	= vp-promon
BINS		= $(BIN_PROMON)

all : $(BINS)

$(PCH) : $(PCH_PATH)/$(PCH_H)
	$(CC) $^ -o $@ $(CFLAGS)

$(BIN_PROMON): $(PCH) $(SDK_HEDS) vp_promon.c $(SDK_OBJS) $(MOD_OBJS)
	$(CC) -o $@ $(patsubst $(PCH) $(SDK_HEDS), , $^) $(CFLAGS) $(LDFLAGS)

aaaa: $(PCH) $(SDK_HEDS) a.c $(SDK_OBJS) $(MOD_OBJS)
	$(CC) -o $@ $(patsubst $(PCH) $(SDK_HEDS), , $^) $(CFLAGS) $(LDFLAGS)

clean:
	$(RM) *.o $(BINS)

