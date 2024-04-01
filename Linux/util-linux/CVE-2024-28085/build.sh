#!/bin/bash
set -xe
gcc -o throw ./exploit/throw.c
gcc -o spy ./exploit/spy.c
gcc -o watch ./exploit/watch.c
