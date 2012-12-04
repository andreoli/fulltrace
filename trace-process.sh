#!/bin/bash

BUFSIZE=2000000

options=$(getopt -o b: -l "bufsize:" -n "trace-process.sh" -- "$@")
if [ $? -ne 0 ]; then
        exit 1
fi

eval set -- "$options"

while true; do
        case "$1" in
                -b|--bufsize) BUFSIZE=$2; shift ;;
                (--) shift; break;;
        esac
        shift
done

CMD="$@"
UPROBES="/tmp/uprobes"
TRACEFILE="/tmp/trace"

set -- $CMD
if ! file -L $1 | grep -q ELF; then
	echo "$1 is not an executable."
	exit 1
fi
set --

make wrapper

echo "tracing $CMD"
echo function_graph | sudo tee /sys/kernel/debug/tracing/current_tracer
echo $BUFSIZE | sudo tee /sys/kernel/debug/tracing/buffer_size_kb
echo 1 | sudo tee /sys/kernel/debug/tracing/tracing_on
echo | sudo tee /sys/kernel/debug/tracing/uprobe_events
cat $UPROBES | sudo tee -a /sys/kernel/debug/tracing/uprobe_events
echo | sudo tee /sys/kernel/debug/tracing/set_ftrace_pid
echo 1 | sudo tee /sys/kernel/debug/tracing/events/uprobes/enable
echo 1 | sudo tee /sys/kernel/debug/tracing/tracing_enabled

sudo ./wrapper $CMD

echo 0 | sudo tee /sys/kernel/debug/tracing/tracing_enabled
echo 0 | sudo tee /sys/kernel/debug/tracing/tracing_on

echo "writing $TRACEFILE"
cat /sys/kernel/debug/tracing/trace > $TRACEFILE

echo 0 | sudo tee /sys/kernel/debug/tracing/events/uprobes/enable
echo | sudo tee /sys/kernel/debug/tracing/uprobe_events

echo nop | sudo tee /sys/kernel/debug/tracing/current_tracer

exit 0
