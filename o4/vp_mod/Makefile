#
#
include ../config.mak

LIB_PATH	=
VPATH		= $(LIBPATH)

HEADS		= $(wildcard *.h)
SRCS		= $(wildcard *.c)
OBJS		= $(patsubst %.c, %.o, $(SRCS))

LIBS     	= #-lrt -lpthread -lm -llicense -lssl # -lmysqlclient # -levent
WARN		= -Wall -Wcast-align -Wsign-compare -unreachable-code #-Wmissing-prototypes #-Wpacked -Wpadded -Winline #-Werror
CFLAGS   	= $(G_CFLAGS) 
LDFLAGS  	= -L$(LIB_PATH) -L/usr/lib/mysql $(LIBS) 

all: $(OBJS)

%.o : %.c 
	$(CC) -c -o $@ $^ $(CFLAGS) $(LDFLAGS) 	

.PHONY: clean
clean:
	$(RM) *.o $(TARGETS)

