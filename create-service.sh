#!/bin/bash

if [ "$EUID" -ne 0 ]
  then echo "Please run this script as root."
  exit
fi

touch cryptomon.service
cat <<EOF > cryptomon.service
[Unit]
Description=Cryptography Monitor Service
After=multi-user.target

[Service]
Type=simple
Restart=always
WorkingDirectory=$(pwd)
ExecStart=/usr/bin/python3 $(pwd)/cryptomon.py

[Install]
WantedBy=multi-user.target
EOF

cp cryptomon.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable cryptomon.service
systemctl start cryptomon.service
