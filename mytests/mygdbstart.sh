#!/bin/bash

# Usage: ./mygdbstart.sh A [--gdb] [--file]

A="$1"
gdb_flag=""
file_flag=""
sample_flag=""
cmw_flag=""


for arg in "$@"
do
  if [ "$arg" == "--gdb" ]; then
    gdb_flag="--gdb"
  elif [ "$arg" == "--file" ]; then
    file_flag="--file"
  elif [ "$arg" == "--vm" ]; then
    file_flag="--vm"
  elif [ "$arg" == "--sample" ]; then
    sample_flag="-p ../../tests/vm/sample.txt -a sample.txt"
  elif [ "$arg" == "--child-mm-wrt" ]; then
    cmw_flag="-p tests/vm/child-mm-wrt -a child-mm-wrt"
  fi
done

if [ "$file_flag" == "--file" ]; then
  make && pintos $gdb_flag --filesys-size=2 -p tests/filesys/base/$A -a $A --swap-size=4 -- -f -q extract run "$A"
elif [ "$file_flag" == "--vm" ]; then
  make && pintos $gdb_flag --filesys-size=2 -p tests/vm/$A -a $A $sample_flag --swap-size=4 $cmw_flag -- -f -q extract run "$A"
else
  make && pintos $gdb_flag --filesys-size=2 -p tests/userprog/$A -a $A --swap-size=4 -- -f -q extract run "$A"
fi
echo "Press Ctrl+a then c to continue"