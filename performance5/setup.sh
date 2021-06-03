#!/bin/bash
pkill -2 server
make -f makefile.srv clean
rm -f Server
make -f makefile.srv all

cp vim-runtime_2%3a8.1.2269-1ubuntu5_all.deb Server

sshpass -p 'root' ssh root@192.168.1.200 "if ! [ -d \"/root/Documents/tesi/performance5\" ]; then mkdir /root/Documents/tesi/performance5; fi"

sshpass -p 'root' rsync -au clt_setup.sh root@192.168.1.200:/root/Documents/tesi/performance5/clt_setup.sh
sshpass -p 'root' rsync -au run.sh root@192.168.1.200:/root/Documents/tesi/performance5/run.sh

sshpass -p 'root' rsync -au aes256ctr.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au aes256ctr.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au api.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au client.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au config.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au fips202.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au fips202.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au ntt.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au ntt.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au packing.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au packing.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au parameters.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au params.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au poly.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au poly.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au polyvec.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au polyvec.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au randombytes.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au randombytes.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au reduce.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au reduce.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au rng.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au rng.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au rounding.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au rounding.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au shared.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au shared.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au sign.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au sign.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au symmetric.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au symmetric-aes.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au symmetric-shake.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au test_dilithium.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au util.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au util.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' rsync -au makefile.clt root@192.168.1.200:/root/Documents/tesi/performance5/makefile.clt

sshpass -p 'root' ssh root@192.168.1.200 "chmod +x /root/Documents/tesi/performance5/clt_setup.sh"
sshpass -p 'root' ssh root@192.168.1.200 "/root/Documents/tesi/performance5/clt_setup.sh"
wait

<< 'MULTILINE-COMMENT'
MULTILINE-COMMENT

chmod 777 -R .
