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

# remove the '-12' suffixes
for tool in "clang" "llc" "llvm-strip" 
do 
    path=$(which $tool-12) 
    sudo ln -s $path ${path%-*} 
done 

# TODO - find out why this doesn't work -MC
sudo snap install --devmode bpftrace

# uname -r returns kernel version
# need linux-tools for kernel specific
apt-get install -y linux-tools-$(uname -r)

# api stuff
apt-get install -y python3-pymongo
apt-get install -y python3-fastapi

# install mongodb
sudo apt-get install gnupg curl
curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc | \
   sudo gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg \
   --dearmor
echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list
sudo apt-get update
sudo apt-get install -y mongodb-org
sudo systemctl daemon-reload
sudo systemctl enable mongod
sudo systemctl start mongod

apt-get install -y python3-tinydb


apt-get install -y python3-tinydb