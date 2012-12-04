#!/bin/bash

SHELL=bash
BASHARG=

usage()
{
cat << EOF
usage: $0 [-b bufsize] [-d] <command>
Full process tracer (userspace, libraries, kernel)
	OPTIONS:
-b	Buffer size
-d	Debug
EOF
}

options=$(getopt -o db: -l "debug,bufsize:" -n "full-trace.sh" -- "$@")
if [ $? -ne 0 ]; then
	exit 1
fi

eval set -- "$options"

while true; do
	case "$1" in
		-d|--debug) BASHARG=-xv ;;
		-b|--bufsize) BUFSIZE=$2; shift ;;
		(--) shift; break;;
	esac
	shift
done

CMD=$@

if [ "$BUFSIZE" != "" ]; then
	TRACEARGS="-b $BUFSIZE"
else
	TRACEARGS=
fi

$SHELL $BASHARG ./finegrain-uprobes.sh $CMD
sudo $SHELL $BASHARG ./trace-process.sh $TRACEARGS $CMD
$SHELL $BASHARG ./rewrite-addresses.sh $CMD
