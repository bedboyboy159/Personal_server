#!/bin/bash

# variables
preload=/home/courses/cs3214/bin/sfi/gurthang/gurthang-preload.so
server=/home/ugrads/majors/longh220/System/Project4/pserv/src/server-fuzz

# input check
if [ $# -lt 1 ]; then
    echo "Usage: $0 /path/to/crash/file"
    exit 1
fi
fpath=$1

# running
LD_PRELOAD=${preload} ${server} -p 50513 -R /home/ugrads/majors/longh220/System/Project4/pserv/src/fuzz_root  < ${fpath}
