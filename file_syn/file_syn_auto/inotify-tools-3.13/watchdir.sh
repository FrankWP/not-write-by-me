#!/bin/bash

path=$1
/usr/local/bin/inotifywait -mrq --timefmt '%d/%m/%y/%H:%M' --format '%T %w %f' -e modify,delete,create,attrib,moved_from,moved_to $path
