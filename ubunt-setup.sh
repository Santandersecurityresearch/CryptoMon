#!/bin/bash

apt-get update
apt-get install -y apt-transport-https ca-certificates curl clang llvm jq
apt-get install -y libelf-dev libpcap-dev libbfd-dev binutils-dev build-essential make 
apt-get install -y linux-tools-common linux-tools-5.15.0-41-generic bpfcc-tools
apt-get install -y python3-pip
apt-get install -y bsdutils
apt-get install -y build-essential
apt-get install -y pkgconf
apt-get install -y llvm-12 clang-12
apt-get install -y clang-format-12
apt-get install -y zlib1g-dev libelf-dev
apt-get install -y protobuf-compiler
apt-get install bpfcc-tools linux-headers-$(uname -r)

# TODO - find out why this doesn't work -MC
sudo snap install --devmode bpftrace

# remove the '-12' suffixes
for tool in "clang" "llc" "llvm-strip" 
do 
    path=$(which $tool-12) 
    sudo ln -s $path ${path%-*} 
done 

# uname -r returns kernel version
# need linux-tools for kernel specific
apt-get install -y linux-tools-$(uname -r)

