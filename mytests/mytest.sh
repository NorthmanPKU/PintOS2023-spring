#!/bin/bash

# Usage: ./mygdbstart.sh A [--gdb] [--file]

A="$1"
file_flag=""

for arg in "$@"
do
  if [ "$arg" == "--file" ]; then
    file_flag="--file"
  elif [ "$arg" == "--vm" ]; then
    file_flag="--vm"
  fi
done

if [ "$file_flag" == "--file" ]; then
  make tests/filesys/base/$A.result
elif [ "$file_flag" == "--vm" ]; then
  make tests/vm/$A.result
else
  make tests/userprog/$A.result
fi
