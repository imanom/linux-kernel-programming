#!/bin/bash

echo -e "Module loaded\n"
sudo insmod proj2.ko int_str="1,2,3,4,5"

echo -e "printing /proc/proj2\n"
cat /proc/proj2

echo -e "\nUnloading module\n"
sudo rmmod proj2.ko

echo -e "Dmesg log: \n"
dmesg | tail -15
