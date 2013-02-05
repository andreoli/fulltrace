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

find_function_exit_point() {
	echo "disas $2" | gdb -q $1 2>/dev/null | grep -E "ret[q]" | awk '{print $1}' | \
		cut -f2 -d"x"
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

# process tracing routines

uprobes_on() {
	echo | sudo tee /sys/kernel/debug/tracing/uprobe_events
	if [ -f $1 ]; then
		cat $1 | while read; do echo $REPLY | \
		sudo tee -a /sys/kernel/debug/tracing/uprobe_events ; done
	else
		echo "WARN: no uprobes, tracing kernel-space functions only"
	fi
	if [ -d /sys/kernel/debug/tracing/events/uprobes ]; then
		echo 1 | sudo tee /sys/kernel/debug/tracing/events/uprobes/enable
	fi
}

ftrace_on() {
	echo function_graph | sudo tee /sys/kernel/debug/tracing/current_tracer
	echo funcgraph-abstime | sudo tee /sys/kernel/debug/tracing/trace_options
	echo funcgraph-proc | sudo tee /sys/kernel/debug/tracing/trace_options
	echo $1 | sudo tee /sys/kernel/debug/tracing/buffer_size_kb
	echo 1 | sudo tee /sys/kernel/debug/tracing/tracing_on
	echo | sudo tee /sys/kernel/debug/tracing/set_ftrace_pid
	echo 1 | sudo tee /sys/kernel/debug/tracing/tracing_enabled
}

ftrace_off() {
	echo 0 | sudo tee /sys/kernel/debug/tracing/tracing_enabled
	echo 0 | sudo tee /sys/kernel/debug/tracing/tracing_on

}

uprobes_off() {

	if [ -d /sys/kernel/debug/tracing/events/uprobes ]; then
		echo 0 | sudo tee /sys/kernel/debug/tracing/events/uprobes/enable
	fi
	echo | sudo tee /sys/kernel/debug/tracing/uprobe_events

}

ftrace_reset() {
	echo nop | sudo tee /sys/kernel/debug/tracing/current_tracer
}

trace_process() {
	sudo ./wrapper $1
}

write_trace() {
	sudo cat /sys/kernel/debug/tracing/trace > $1
	shortname=${2:0:7}
	first=$(grep -nE "=>\s+${shortname}-[[:digit:]]+" $1 | head -n 1 | cut -f1 -d:)
	first=$((first-2))
	last=$(grep -nE "${shortname}-[[:digit:]]+\s+=>" $1 | tail -n 1 | cut -f1 -d:)
	last=$((last+2))
	# If a context switch out has been found but it happened before
	# the first context switch in, do not trim the trace
	if (( $last <= $first )); then
		return
	fi
	# Trim the trace at its beginning only if the index of the first
	# context switch in is positive (in the other case, the trace
	# begins "in medias res")
	if (( $first > 0 )); then
		sed -i -e "1,$first d;" $1
		# We know that we trimmed the trace output until the line
		# whose index is kept in the "first" variable: compute the
		# new position of the last context switch out
		last=$((last-first))
	fi
	# If a context switch out has been found, trim the tail of the trace
	if (( $last > 2 )); then
		sed -i -e "$last,$ d;" $1
	fi
}

# trace decoding routines

rewrite-address-split-trace() {
	tracefile=$1
	dsos_addresses=$(grep "\/\* p_.* (0x.*) \*\/" $tracefile | awk '{print $8}' | sort | uniq)
	for a in $dsos_addresses; do
		dso=$(echo $a | cut -f1-2 -d"_")
		if [[ ! -r $DSOPREFIX/$dso ]]; then
			dso_file=$(ls $DSOPREFIX/$dso*)
		else
			dso_file=$DSOPREFIX/$dso
		fi
		dso_decoded_name=$(basename $dso_file)
		offset=$(echo $a | cut -f3 -d"_" | tr -d ":")
		symbol=$(grep $offset $dso_file | tail -n 1 | cut -f2 -d" ")
		entorex=$(grep $offset $dso_file | tail -n 1 | cut -f3 -d" ")

		echo "dso:$dso, offset:$offset, symbol:$symbol"
		sed -i -e "s/${dso}_${offset}:/${dso_decoded_name:2}:${symbol}:${entorex}/" $tracefile
	done
}

# The following awk script keeps all the trace lines that:
# - don't match with an uprobe event;
# - match with an uprobe event and have the process basename as process ID.
remove-spurious-uprobes() {
	tracefile=$1
	shortname=${2:0:7}
	newname=$1-r
	awk -v name=$shortname '{
		if ( /[0-9]+\)[[:blank:]]+.*\/\*.*\*\/ / ) {
			split($4, id, "-"); 
			if (id[1] == name) {
				print $0
			}
		} 
		else {
			print $0
		}
	}' $tracefile > $newname
	cat $newname > $tracefile
	rm $newname
}

# The following awk-based function computes the duration of userspace functions
# and adds it to the trace output.
#
# The awk script uses two associative arrays to track the recursion level of
# entry-exit event pairs ("level") and store the absolute timestamp of entry
# uprobe events ("entry"). Initially, both arrays are empty.
# The access key of both the associative arrays always contain the kernel PID
# of the process that executed the action, so that the function can correctly
# separate events from different threads.
# The algorithm applied by awk on each line is explained in more detail in the
# following comment.
# * if the line is an entry uprobe event:
#   |__ increase the recursion level of the symbol for the given PID
#       (level[symbol:pid]++);
#   |__ store the timestamp for the call of that level
#       (entry[symbol:pid:level[symbol:pid]] = absolute_timestamp);
# * if the line is an exit uprobe event:
#   |__ if the function symbol has a valid recursion level (> 0):
#       |__ get the matching entry event timestamp according to the recursion
#           level of the symbol and the PID;
#       |__ compute the difference between the two timestamps (in a
#           timeval_subtract() fashion);
#       |__ format the computed value in a 5-digit field and print it into the
#           line of the trace output;
#       |__ decrease the recursion level and delete the "entry" element for
#           that symbol and recursion level ("pop" from the stack).
add-userspace-functions-duration() {
	tracefile=$1
	newname=$1-t
	awk -F: '{
		if ( /\/\*.*:.*:enter.*\*\/ / ) {
			split($0, line, " "); 
			split(line[4], id, "-"); 
			level[$2":"id[2]]++; 
			entry[$2":"id[2]":"level[$2":"id[2]]] = line[1];
		} 
		if ( /\/\*.*:.*:exit.*\*\/ / ) {
			split($0, line, " "); 
			split(line[4], id, "-"); 
			if (level[$2":"id[2]]) {
				split(line[1], x, "."); 
				xsec = x[1]; xusec = x[2]; 
				split(entry[$2":"id[2]":"level[$2":"id[2]]], y, "."); 
				ysec = y[1]; 
				yusec = y[2]; 
				if (xusec < yusec) {
					nsec = (yusec - xusec) / 1000000 + 1; 
					yusec = yusec - (1000000 * nsec); 
					ysec = ysec + nsec;
				} 
				if (xusec - yusec > 1000000) {
					nsec = (xusec - yusec) / 1000000;
					yusec = yusec + (1000000 * nsec); 
					ysec = ysec - nsec;
				} 
				resultsec = xsec - ysec; 
				resultusec = xusec - yusec; 
				split($0, msg, "|"); 
				printf "%s|%s|   %-5.5s us    |%s\n", msg[1], msg[2], sprintf("%.2f", resultusec), msg[4]; 
				delete entry[$2":"id[2]":"level[$2":"id[2]]]; 
				level[$2":"id[2]]--;
			}
		} 
		else {
			print $0
		}
	}' $tracefile > $newname
	cat $newname > $tracefile
	rm $newname
}

# Filters
EVENTS_DIR="/sys/kernel/debug/tracing/events"
SUBSYSTEMS=$(sudo ls -l $EVENTS_DIR | grep "^d" | awk '{ print $9 }')

include_subsystems() {
	for s in $1; do
		echo -n "Including subsystem $s "
		echo 1 | sudo tee $EVENTS_DIR/$s/enable
	done
}

exclude_subsystems() {
	for s in $1; do
		echo -n "Excluding subsystem $s "
		echo 0 | sudo tee $EVENTS_DIR/$s/enable
	done
}

handle_subsystems() {
	if [ "$ALLOWED_SUBSYS" != "" ]; then
		EXCLUDED_SUBSYS=$SUBSYSTEMS
		for s in ${ALLOWED_SUBSYS//,/ }; do
			EXCLUDED_SUBSYS=$(echo $EXCLUDED_SUBSYS | sed "s/\b$s\b//g")
		done
		ALLOWED_SUBSYS=$(echo ${ALLOWED_SUBSYS//,/ } | sed "s/\bftrace\b//g")
		ALLOWED_SUBSYS=$(echo ${ALLOWED_SUBSYS//,/ } | sed "s/\buprobes\b//g")
		EXCLUDED_SUBSYS=$(echo $EXCLUDED_SUBSYS | sed "s/\bftrace\b//g")
		EXCLUDED_SUBSYS=$(echo $EXCLUDED_SUBSYS | sed "s/\buprobes\b//g")
		include_subsystems "${ALLOWED_SUBSYS//,/ }"
		exclude_subsystems "$EXCLUDED_SUBSYS"
	fi
}

SHELL=bash
BASHARG=
TMP="/tmp"
TRACEFILE="$TMP/trace"
TRACEPREFIX="$TMP/trace.split"
TRACEFILE_DECODED="$TMP/trace.decoded"
UPROBES="$TMP/uprobes"
TOVISIT="$TMP/tovisit"
VISITED="$TMP/visited"
SYMBOLS="$TMP/symbols"
DSOPREFIX="$TMP"

usage()
{
cat << EOF
usage: $0 [-b|--bufsize bufsize] [-c|--clean] [-d|--debug] [-h|--help]
          [-o|--output] [-t|--trace] [-u|--uprobes]
          [-k|--ksubsys subsys1,...] -- <command> <arg>...

Full process tracer (userspace, libraries, kernel)
OPTIONS:
-b|--bufsize	Set the per-cpu buffer size (KB)
-c|--clean	Clean temporary files
-d|--debug	Debug output
-h|--help	This help
-o|--output	Output decoding
-t|--trace	Process tracing
-u|--uprobes	Uprobes creation
-k|--ksubsys    Enable traces for listed subsystems
EOF
}

options=$(getopt -o cdb:hotuk: -l "clean,debug,bufsize:,help,output,tracing,uprobes,ksubsys:" -n "full-trace.sh" -- "$@")
if [ $? -ne 0 ]; then
	exit 1
fi

sudo -v

eval set -- "$options"
do_uprobes=0
do_tracing=0
do_decoding=0

while true; do
	case "$1" in
		-c|--clean) cleanup $TOVISIT $VISITED $SYMBOLS $UPROBES $TRACEFILE $TRACEPREFIX* /tmp/p_*; exit 0;;
		-d|--debug) BASHARG=-xv ;;
		-b|--bufsize) BUFSIZE=$2; shift ;;
		-h|--help) usage; exit 0 ;;
		-o|--output) do_decoding=1 ;;
		-t|--tracing) do_tracing=1 ;;
		-u|--uprobes) do_uprobes=1 ;;
		-k|--ksubsys) ALLOWED_SUBSYS=$2; shift ;;
		(--) shift; break;;
	esac
	shift
done


if [[ "$BUFSIZE" == "" ]]; then
	
	# The interval in /sys/devices/systen/cpu/possible may not start from zero, so I calculate it
	last_possible_cpu=$(cat /sys/devices/system/cpu/possible | cut -f 2 -d "-")
	first_possible_cpu=$(cat /sys/devices/system/cpu/possible | cut -f 1 -d "-")
	nr_possible_cpu=$(( last_possible_cpu - first_possible_cpu + 1 ))
	
	free=$(free -k | grep ^Mem  | awk '{print $4}')
	BUFSIZE=$(($free / 4 / $nr_possible_cpu))
fi

CMD="$@"
CMDNAME=$(which $1)

if [[ $do_uprobes == 1 ]]; then
	if ! file -L $CMDNAME | grep -q ELF; then
		echo "$CMDNAME is not an executable."
		exit 1
	fi

	file -L $CMDNAME | grep -q "not stripped"; has_static_symtable=$?
	mkdir $TOVISIT $VISITED $SYMBOLS

	dsos=$(find_dsos $CMDNAME)
	symbols=$(find_program_function_symbols $CMDNAME $has_static_symtable)
	for s in $symbols; do
		touch $SYMBOLS/$s
	done

	symbols=$(find_used_library_function_symbols $CMDNAME $has_static_symtable)
	for s in $symbols; do
		touch $TOVISIT/$s
	done

	symbols=$(find_dynamic_loader_symbols $(echo $dsos | grep -o -E "/lib(|32|64)/ld\-(.*)"))
	for s in $symbols; do
		touch $TOVISIT/$s
	done

	while [[ "$(ls -A $TOVISIT 2>/dev/null)" != "" ]]; do
		sym=$(ls $TOVISIT/* | head -n 1)
		cp $sym $VISITED
		mv $sym $SYMBOLS
		sym=$(basename $sym)
		dso=$(find_dso_owning_symbol "$dsos" $sym)
		sym_info=$(print_symbol_info $dso $sym)
		if symbol_is_weak "$sym_info"; then
			addr=$(echo $sym_info | awk '{print $1}')
			strong_sym=$(lookup_real_symbol $dso $addr)
			if [[ $strong_sym != "" ]]; then
				sym=$strong_sym
			fi
		fi
		functions_called=$(find_functions_invoked_by_library_function $dso $sym)
		for fc in $functions_called; do
			if ! ls $VISITED | grep -q $fc; then
				touch $TOVISIT/$fc
			fi
		done
	done

	for s in $(ls $SYMBOLS/*); do
		sym=$(basename $s)
		dso=$(find_dso_owning_symbol "$dsos $CMDNAME" $sym)
		start_addr=$(find_start_addr $dso)
		abs_addr=$(find_symbol_abs_address $dso $sym)
		for a in $abs_addr; do
			rel_addr=$(hex_sub "0x$a" $start_addr)
			echo "p $dso:$rel_addr" >> $UPROBES
			if [[ "$dso" == "$CMDNAME" ]]; then
				printf "0x%x %s enter\n" "$rel_addr" $sym >> /tmp/p_$(basename $dso)
			else
				printf "0x%x %s enter\n" "$rel_addr" $sym >> /tmp/p_$(basename $dso | sed -ne 's/^\([[:alpha:]]\+\)\(.*\)$/\1/p')
			fi
		done
		abs_addr=$(find_function_exit_point $dso $sym)
		for a in $abs_addr; do
			rel_addr=$(hex_sub "0x$a" $start_addr)
			echo "p $dso:$rel_addr" >> $UPROBES
			if [[ "$dso" == "$CMDNAME" ]]; then
				printf "0x%x %s exit\n" "$rel_addr" $sym >> /tmp/p_$(basename $dso)
			else
				printf "0x%x %s exit\n" "$rel_addr" $sym >> /tmp/p_$(basename $dso | sed -ne 's/^\([[:alpha:]]\+\)\(.*\)$/\1/p')
			fi
		done
	done

	sort -u $UPROBES > $UPROBES.sortuniq
	mv $UPROBES.sortuniq $UPROBES
fi

if [[ $do_tracing == 1 ]]; then
	echo "tracing $CMD"
	handle_subsystems
	ftrace_on $BUFSIZE
	uprobes_on $UPROBES
	trace_process "$CMD"
	ftrace_off

	echo "writing $TRACEFILE"
	write_trace $TRACEFILE $(basename $CMDNAME)

	uprobes_off
	ftrace_reset
fi

if [[ $do_decoding == 1 ]]; then
	nr_cpu=$(lscpu | grep ^CPU\(s\) | awk '{print $2}')
	if [[ "$nr_cpu" -gt 1 ]]; then
		postfix="s"
	fi
	echo "splitting the trace in $nr_cpu part$postfix"
	total_lines=$(wc -l < $TRACEFILE)
	partial_lines=$(($total_lines/$nr_cpu+1))
	split -l $partial_lines $TRACEFILE $TRACEPREFIX

	trap "killall full-trace.sh" SIGINT SIGTERM

	for f in $(ls $TRACEPREFIX*); do
		rewrite-address-split-trace $f &
	done
	wait

	for f in $(ls $TRACEPREFIX*); do
		remove-spurious-uprobes $f $(basename $CMDNAME) &
	done
	wait

	cat $TRACEPREFIX* > $TRACEFILE_DECODED

	# We cannot split the work of adding the duration of userspace
	# functions between different threads, as corresponding entry and
	# exit uprobe events could be located in different parts of the trace
	add-userspace-functions-duration $TRACEFILE_DECODED
fi
