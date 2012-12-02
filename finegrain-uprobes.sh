#!/bin/bash

symbol_has_static_table() {
	# FIXME: Does this work if system language is not English?
	[ -n $(objdump -t $1 | grep -qw "no symbols")$? ]
}

find_dsos() {
	ldd $CMD | grep -Ev 'gate|vdso' | sed -e 's/(\(.*\))//' | \
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

CMD=$1
UPROBES="/tmp/uprobes"
STACK="/tmp/stack"
WASONSTACK="/tmp/wasonstack"
SYMBOLS="/tmp/symbols"

if ! file -L $CMD | grep -q ELF; then
	echo "$CMD is not an executable."
	exit 1
fi
file -L $CMD | grep -q "not stripped"; has_static_symtable=$?
mkdir $STACK $WASONSTACK $SYMBOLS

dsos=$(find_dsos)
symbols=$(find_program_function_symbols $CMD $has_static_symtable)
for s in $symbols; do
	touch $SYMBOLS/$s
done

symbols=$(find_used_library_function_symbols $CMD $has_static_symtable)
for s in $symbols; do
	touch $STACK/$s
done

symbols=$(find_dynamic_loader_symbols $(echo $dsos | grep -o -E "/lib(|32|64)/ld\-(.*)"))
for s in $symbols; do
	touch $STACK/$s
done

while [[ "$(ls -A $STACK 2>/dev/null)" != "" ]]; do
	sym=$(ls $STACK/* | head -n 1)
	cp $sym $WASONSTACK
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
		if ! ls $WASONSTACK | grep -q $fc; then
			touch $STACK/$fc
		fi
	done
done

for s in $(ls $SYMBOLS/*); do
	sym=$(basename $s)
	dso=$(find_dso_owning_symbol "$dsos $CMD" $sym)
	start_addr=$(find_start_addr $dso)
	abs_addr=$(find_symbol_abs_address $dso $sym)
	for a in $abs_addr; do
		rel_addr=$(hex_sub "0x$a" $start_addr)
		echo "p $dso:$rel_addr" >> $UPROBES
		if [[ "$dso" == "$CMD" ]]; then
			printf "0x%x %s\n" "$rel_addr" $sym >> /tmp/p_$(basename $dso)
		else
			printf "0x%x %s\n" "$rel_addr" $sym >> /tmp/p_$(basename $dso | sed -ne 's/^\([[:alpha:]]\+\)\(.*\)$/\1/p')
		fi

	done
done

exit 0
