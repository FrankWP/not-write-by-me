CC                = gcc
CFLAG             = -Wall -Werror -O2 -o
#CFLAG             = -ggdb -o
INC               = -I./include
LIB_FILE          = -lpcap
OPTION            = -DLOG_ERROR \
					-DLOG_WARNING 
#-DLOG_DEBUG \
#-DLOG_NOTICE 

FILE_NET_OSPF     = src/net_ospf.c src/common.c src/config.c
FILE_HELLO_SEND   = test/ospf_hello.c
FILE_IP_CAL       = src/ip_cal.c src/common.c

OBJ_NET_OSPF      = ./src/net_ospf
OBJ_HELLO_SEND    = ./test/test_hello
OBJ_IP_CAL        = ./src/ip_cal

.PHONY:
all: clean $(OBJ_NET_OSPF) $(OBJ_IP_CAL) install

$(OBJ_NET_OSPF): $(FILE_NET_OSPF)
	$(CC) $(CFLAG) $@ $^ $(INC) $(LIB_FILE) $(OPTION)

$(OBJ_HELLO_SEND): $(FILE_HELLO_SEND)
	$(CC) $(CFLAG) $@ $^ $(INC) $(LIB_FILE) $(OPTION)

$(OBJ_IP_CAL): $(FILE_IP_CAL)
	$(CC) $(CFLAG) $@ $^ $(INC) $(LIB_FILE) $(OPTION)

.PHONY: install
install:
	cp -af ./src/net_ospf ./other/usr/local/hawk/net_ospf/net_ospf
	cp -af ./src/ip_cal ./other/usr/local/hawk/net_ospf/ip_cal
	# create target
	mkdir ./target
	cp -af ./other/* ./target/
	cp -af ./etc ./target/
	../include/make_img.sh inside "./target"
	../include/make_img.sh outside "./target"

.PHONY: clean
clean: 
	rm -rf *.o $(OBJ_NET_OSPF) $(OBJ_HELLO_SEND) $(OBJ_IP_CAL)
	rm -rf ./target
	rm -rf ./other/usr/local/hawk/net_ospf/net_ospf
	rm -rf ./other/usr/local/hawk/net_ospf/ip_cal
	rm -rf ./include/tags
	rm -rf ./src/tags
	rm -rf tags
