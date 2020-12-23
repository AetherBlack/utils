#!/bin/sh -e
#
### BEGIN INIT INFO
# Provides:          Aether
# Required-Start:    $all
# Required-Stop:
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: HTTPS Proxy
### END INIT INFO
    
DAEMON="/path/to/main.py"
PID_FILE="/path/to/pid/main.ini"
DAEMONUSER="root"
ARGS=""
daemon_NAME="main.py"
    
PATH="/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin"
    
test -x $DAEMON || exit 0
. /lib/lsb/init-functions
 
case "$1" in
    start)
        log_begin_msg "Starting $daemon_NAME"
        python3.8 $DAEMON &
    ;;
    stop)
        log_begin_msg "Stopping $daemon_NAME"
        test -e $PID_FILE && kill -9 $(cat $PID_FILE) && rm $PID_FILE
    ;;
    restart|reload|force-reload)
        $0 stop
        $0 start
    ;;
    status)
        if test -e $PID_FILE && test -d /proc/$(cat $PID_FILE) ; then
            log_success_msg "Service: $daemon_NAME is running"
        else
            log_success_msg "Service: $daemon_NAME is not running"
        fi
    ;;
    *)
        log_success_msg "Usage: /etc/init.d/$daemon_NAME {start|stop|restart|reload}"
        exit 1
    ;;
esac
exit 0
