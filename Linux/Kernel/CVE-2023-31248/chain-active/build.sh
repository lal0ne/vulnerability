#!/bin/sh

gcc -fdiagnostics-color=always -no-pie -g -Wall -O0 -std=c17 exploit.c -o chain-active -lmnl -lnftnl
gcc monke.c -o monke
