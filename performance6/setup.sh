#!/bin/bash
make -f makefile.srv clean
pkill -2 server
make -f makefile.srv all

#openssl genrsa -out srvprvkey.pem 2048
#openssl rsa -in srvprvkey.pem -outform PEM -pubout -out srvpubkey.pem 

#sshpass -p 'root' ssh root@192.168.1.200 "rm -rf /root/Documents/tesi/performance6"
sshpass -p 'root' ssh root@192.168.1.200 "if ! [ -d \"/root/Documents/tesi/performance6\" ]; then mkdir /root/Documents/tesi/performance6; fi"

sshpass -p 'root' rsync -au makefile.clt root@192.168.1.200:/root/Documents/tesi/performance6/makefile.clt
sshpass -p 'root' rsync -au client.c root@192.168.1.200:/root/Documents/tesi/performance6/client.c
sshpass -p 'root' rsync -au shared.c root@192.168.1.200:/root/Documents/tesi/performance6/shared.c
sshpass -p 'root' rsync -au shared.h root@192.168.1.200:/root/Documents/tesi/performance6/shared.h
sshpass -p 'root' rsync -au parameters.h root@192.168.1.200:/root/Documents/tesi/performance6/parameters.h
sshpass -p 'root' rsync -au util.c root@192.168.1.200:/root/Documents/tesi/performance6/util.c
sshpass -p 'root' rsync -au util.h root@192.168.1.200:/root/Documents/tesi/performance6/util.h
sshpass -p 'root' rsync -au clt_setup.sh root@192.168.1.200:/root/Documents/tesi/performance6/clt_setup.sh
sshpass -p 'root' rsync -au run.sh root@192.168.1.200:/root/Documents/tesi/performance6/run.sh
sshpass -p 'root' ssh root@192.168.1.200 "chmod +x /root/Documents/tesi/performance6/clt_setup.sh"
sshpass -p 'root' ssh root@192.168.1.200 "/root/Documents/tesi/performance6/clt_setup.sh"
wait

cp -f linux-libc-dev_5.4.0-70.78_arm64.deb Server

#cp -f srvprvkey.pem Server
#sshpass -p 'root' scp srvpubkey.pem root@192.168.1.200:/root/Documents/tesi/performance6/Client
#cp -f srvpubkey.pem Client

rm -f *.o

chmod 777 -R .
