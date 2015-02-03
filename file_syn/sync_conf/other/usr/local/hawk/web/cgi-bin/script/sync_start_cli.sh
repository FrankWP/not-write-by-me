#该脚本用于执行文件同步客户端程序
#!/bin/bash

PATH=/bin:/sbin:/usr/bin:/usr/sbin
SYNPROC_PATH=/usr/local/hawk/ha/sync_config
EXEC=syn_file_cli

$SYNPROC_PATH/$EXEC >/dev/null 2>&1 &
