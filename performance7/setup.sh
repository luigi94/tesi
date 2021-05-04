#!/bin/bash
pkill -2 server
make -f makefile.srv clean
rm -f Server
make -f makefile.srv all

cp linux-libc-dev_5.4.0-70.78_arm64.deb Server

sshpass -p 'root' ssh root@192.168.1.200 "if ! [ -d \"/root/Documents/tesi/performance7\" ]; then mkdir /root/Documents/tesi/performance7; fi"

sshpass -p 'root' rsync -au clt_setup.sh root@192.168.1.200:/root/Documents/tesi/performance7/clt_setup.sh
sshpass -p 'root' rsync -au run.sh root@192.168.1.200:/root/Documents/tesi/performance7/run.sh

sshpass -p 'root' rsync -au api.h root@192.168.1.200:/root/Documents/tesi/performance7
sshpass -p 'root' rsync -au client.c root@192.168.1.200:/root/Documents/tesi/performance7
sshpass -p 'root' rsync -au codec.c root@192.168.1.200:/root/Documents/tesi/performance7
sshpass -p 'root' rsync -au common.c root@192.168.1.200:/root/Documents/tesi/performance7
sshpass -p 'root' rsync -au fft.c root@192.168.1.200:/root/Documents/tesi/performance7
sshpass -p 'root' rsync -au fpr.c root@192.168.1.200:/root/Documents/tesi/performance7
sshpass -p 'root' rsync -au fpr.h root@192.168.1.200:/root/Documents/tesi/performance7
sshpass -p 'root' rsync -au inner.h root@192.168.1.200:/root/Documents/tesi/performance7
sshpass -p 'root' rsync -au katrng.c root@192.168.1.200:/root/Documents/tesi/performance7
sshpass -p 'root' rsync -au katrng.h root@192.168.1.200:/root/Documents/tesi/performance7
sshpass -p 'root' rsync -au keygen.c root@192.168.1.200:/root/Documents/tesi/performance7
sshpass -p 'root' rsync -au nist.c root@192.168.1.200:/root/Documents/tesi/performance7
sshpass -p 'root' rsync -au parameters.h root@192.168.1.200:/root/Documents/tesi/performance7
sshpass -p 'root' rsync -au rng.c root@192.168.1.200:/root/Documents/tesi/performance7
sshpass -p 'root' rsync -au shake.c root@192.168.1.200:/root/Documents/tesi/performance7
sshpass -p 'root' rsync -au shared.c root@192.168.1.200:/root/Documents/tesi/performance7
sshpass -p 'root' rsync -au shared.h root@192.168.1.200:/root/Documents/tesi/performance7
sshpass -p 'root' rsync -au sign.c root@192.168.1.200:/root/Documents/tesi/performance7
sshpass -p 'root' rsync -au vrfy.c root@192.168.1.200:/root/Documents/tesi/performance7
sshpass -p 'root' rsync -au makefile.clt root@192.168.1.200:/root/Documents/tesi/performance7/makefile.clt

sshpass -p 'root' ssh root@192.168.1.200 "chmod +x /root/Documents/tesi/performance7/clt_setup.sh"
sshpass -p 'root' ssh root@192.168.1.200 "/root/Documents/tesi/performance7/clt_setup.sh"
wait

<< 'MULTILINE-COMMENT'
MULTILINE-COMMENT

chmod 777 -R .
