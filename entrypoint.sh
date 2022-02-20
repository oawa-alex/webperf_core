#!/bin/sh

# `$*` expands the `args` supplied in an `array` individually
# or splits `args` in a string separated by whitespace.
sh -c "echo $*"
ls
cd /webperf-core
ls
python default.py -h