#!/bin/bash

sudo insmod perftop.ko 
echo -e "Module loaded\n"

echo -e "printing /proc/perftop...\n"
cat /proc/perftop

echo -e "\nUnloading module\n"
sudo rmmod perftop.ko

