################################################################
# Copyright (C), 2006-2014, Legendsec Technology Co., Ltd.     #
# FileName:  MakeFile                                          #
#  Project:  file synchroizition							   #
#   Author:  wangyonga                                         #
#     Date:  15/01/29                                          #
#     Desc:  Build the program.                                #
################################################################

CC                = gcc
CFLAG             = -Wall -Werror -Wuninitialized -Wunused -O2 -o 

FILE_SYN_CLI	  = src/syn_file_cli.c 
FILE_SYN_SER      = src/syn_file_ser.c

OBJ_SYN_CLI		  = ./src/syn_file_cli
OBJ_SYN_SER		  = ./src/syn_file_ser

.PHONY:
all: clean $(OBJ_SYN_CLI) $(OBJ_SYN_SER) install

$(OBJ_SYN_CLI): $(FILE_SYN_CLI)
	$(CC) $(CFLAG) $@ $^ 

$(OBJ_SYN_SER): $(FILE_SYN_SER)
	$(CC) $(CFLAG) $@ $^ 

.PHONY: install
install:
	strip $(OBJ_SYN_CLI)
	strip $(OBJ_SYN_SER)
	mkdir -p target/usr/local/hawk/ha/sync_config/
	cp -af src/syn_file_cli target/usr/local/hawk/ha/sync_config/
	cp -af src/syn_file_ser target/usr/local/hawk/ha/sync_config/
	# create target
	cp -af other/* target/
	cp -af etc target/


.PHONY: clean
clean: 
	rm -rf src/*.o $(OBJ_SYN_CLI) $(OBJ_SYN_SER)
	rm -rf ./target
	rm -rf ./src/tags
	rm -rf tags
