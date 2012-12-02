#!/bin/bash

CMD=$1
UPROBES="/tmp/uprobes"
TRACEFILE="/tmp/trace"
TRACEPREFIX="/tmp/trace.split"
TRACEFILE_DECODED="/tmp/trace.decoded"

nr_cpu=$(lscpu | grep ^CPU\(s\) | awk '{print $2}')
if [[ "$nr_cpu" -gt 1 ]]; then
	postfix="s"
fi
echo "splitting the trace in $nr_cpu part$postfix"
split -n $nr_cpu $TRACEFILE $TRACEPREFIX

for f in $(ls $TRACEPREFIX*); do
	./rewrite-address-split-trace.sh $f &
done

wait
echo "fine"

cat $TRACEPREFIX* > $TRACEFILE_DECODED
exit 0
