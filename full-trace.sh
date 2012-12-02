#!/bin/bash


./finegrain-uprobes.sh $1
./trace-process.sh $1
./rewrite-addresses.sh $1
#./clean.sh
