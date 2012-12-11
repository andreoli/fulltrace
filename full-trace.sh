#!/bin/bash

# DL table parsing routines

symbol_has_static_table() {
	# FIXME: Does this work if system language is not English?
	[ -n $(objdump -t $1 | grep -qw "no symbols")$? ]
}

find_dsos() {
	ldd $1 | grep -Ev 'gate|vdso' | sed -e 's/(\(.*\))//' | \
	sed -e 's|^\([^/]*\)\(.*\)$|\2|'
}

find_symbol_abs_address() {
	if symbol_has_static_table $1; then
		ad=$(objdump -t $1 | grep "F .text" | grep -w $2 | awk '{print $1}')
		if [ "$ad" != "" ]; then echo $ad; return; fi
	fi
	echo "$(objdump -T $1 | grep "F .text" | grep -w $2 | awk '{print $1}')"
}

find_start_addr() {
	readelf -l $1 | grep -A1 LOAD | grep -B1 "R E" | \
	grep LOAD | awk '{print $4}'
}

find_functions_invoked_by_library_function() {
	echo "disas $2" | gdb -q $1 2>/dev/null | grep -E "callq([^#]+)<" | grep -v "@" | \
		grep -v -w $2 | awk '{print $5'} | sed -e 's/<\(.*\)>/\1/'
}

lookup_real_symbol() {
	if symbol_has_static_table $1; then
		sy=$(objdump -t $1 | grep -E "$2\s+g\s+DF\s+.text" | awk '{print $7}')
		if [ "$sy" != "" ]; then echo $sy; return; fi
	fi
	objdump -T $1 | grep -E "$2\s+g\s+DF\s+.text" | awk '{print $7}'
}

symbol_is_weak() {
	symtype=$(echo $1 | awk '{print $2}')
	if [[ "$symtype" == "w" ]]; then
		return 0
	else
		return 1
	fi
}

print_symbol_info() {
	objdump -T $1 | grep -w $2
}

find_dso_owning_symbol() {
	for d in $1; do
		if symbol_has_static_table $d; then
			if objdump -t $d | grep -qw $2; then
				echo $d
				return
			fi
		fi
		if objdump -T $d | grep -qw $2; then
			echo $d
			return
		fi
	done
}

find_dynamic_loader_symbols() {
	if symbol_has_static_table $1; then
		sy=$(objdump -t $1 | grep -E "g\s+F .text" | awk '{print $7}')
		if [ "$sy" != "" ]; then echo $sy; return; fi
	fi
	objdump -T $1 | grep -E "g\s+DF .text" | awk '{print $7}'
}

find_used_library_function_symbols() {
	if [[ $2 == 0 ]]; then
		objdump -t $1 | grep -E "F \*UND\*" | awk '{print $5}' | cut -f1 -d"@"
	else
		objdump -T $1 | grep -E "DF \*UND\*" | awk '{print $6}'
	fi
}

find_program_function_symbols() {
	if [[ $2 == 0 ]]; then
		objdump -t $1 | grep -E "g\s+F .text" | awk '{print $6}'
	else
		objdump -T $1 | grep -E "g\s+DF .text" | awk '{print $7}'
	fi
}

hex_sub() {
	printf "0x%x" $(($1-$2))
}

cleanup() {
	rm -rf $@
}

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
