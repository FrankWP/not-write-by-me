ifndef TOPMTP_CONFIG_MAK
TOPMTP_CONFIG_MAK=1

#WARN		= -Wall -Winvalid-pch -unreachable-code #-Wcast-align -Wsign-compare #-Wmissing-prototypes -Wpacked -Wpadded -Winline #-Werror
G_WARN	= -Wall -Winvalid-pch -unreachable-code 
G_LIBS	= -lrt -lz -lm -ldl -L/lib64-mtp
G_CFLAGS= $(G_WARN) -fPIC
CROSS_COMPILE = #arm-linux-
G_LIBPATH= -Wl,-rpath,/lib64-MTP
#CC      = $(CROSS_COMPILE)g++ -g
CC      = $(CROSS_COMPILE)g++ -m64 -g
#CC      = $(CROSS_COMPILE)gcc
LD      = $(CROSS_COMPILE)ld
AR      = $(CROSS_COMPILE)ar
OBJDUMP = $(CROSS_COMPILE)objdump
OBJCOPY = $(CROSS_COMPILE)objcopy
NM      = $(CROSS_COMPILE)nm
#export CFLAGS CPPFLAGS CC LD AR OBJDUMP NM MAKE

CP		= cp -f
RM		= rm -f
CD		= cd

endif #TOPMTP_CONFIG_MAK
