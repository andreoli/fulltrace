#!/bin/bash

UPROBES="/tmp/uprobes"

if ! test -r $1; then
	echo "$1 is not readable."
	exit 1
fi

tracefile=$1
dsos_addresses=$(grep "\/\* p_.* (0x.*) \*\/" $tracefile | awk '{print $4}' | sort | uniq)
for a in $dsos_addresses; do
	dso=$(echo $a | cut -f1-2 -d"_")
	if [[ ! -r /tmp/$dso ]]; then
		dso_file=$(ls /tmp/$dso*)
	else
		dso_file=/tmp/$dso
	fi
	dso_decoded_name=$(basename $dso_file)
	offset=$(echo $a | cut -f3 -d"_" | tr -d ":")
	symbol=$(grep $offset $dso_file | tail -n 1 | cut -f2 -d" ")

	echo "dso:$dso, offset:$offset, symbol:$symbol"
	sed -i -e "s/${dso}_${offset}:/${dso_decoded_name:2}:${symbol}/" $tracefile
done

exit 0
