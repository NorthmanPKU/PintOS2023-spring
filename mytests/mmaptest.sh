#!/bin/bash

for arg in mmap-read mmap-write mmap-shuffle mmap-twice mmap-unmap mmap-exit mmap-clean mmap-close mmap-remove mmap-bad-fd mmap-inherit mmap-null mmap-zero mmap-misalign mmap-over-code mmap-over-data mmap-over-stk mmap-overlap
do
  echo "Running $arg"
  ./mytest.sh $arg --vm --sample
done