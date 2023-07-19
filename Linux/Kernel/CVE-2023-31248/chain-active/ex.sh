#!/bin/bash

while true; do
    cp x /tmp/x
    cp dummy /tmp/dummy
    cp monke /tmp/monke
    chmod +x /tmp/x /tmp/dummy /tmp/monke
    ./chain-active
    /tmp/dummy > /dev/null 2>&1
    /tmp/monke
done
