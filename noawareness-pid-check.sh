#!/bin/sh

# noawareness-pid-check.sh -- by Daniel Roberson
# -- simple script to respawn noawareness if it dies.
# -- meant to be placed in your crontab!
# --
# -- * * * * * /path/to/noawareness-pid-check.sh

# Season to taste:
PIDFILE="/var/run/noawareness.pid"
BINPATH="/root/noawareness/noawareness -d -p $PIDFILE"

if [ ! -f $PIDFILE ]; then
    # PIDFILE doesnt exist!
    echo "noawareness not running. Attempting to start.."
    $BINPATH
    exit
else
    # PID file exists. check if its running!
    kill -0 "$(head -n 1 $PIDFILE)" 2>/dev/null
    if [ $? -eq 0 ]; then
        exit 0
    else
        echo "noawareness not running. Attempting to start.."
        $BINPATH
    fi
fi

