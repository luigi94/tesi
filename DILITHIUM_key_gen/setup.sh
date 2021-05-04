#!/bin/bash
make -f makefile.srv clean
make -f makefile.srv all

./key_gen

mv -f prv_key Server
cp -f pub_key Client

cp linux-libc-dev_5.4.0-70.78_arm64.deb Server

sshpass -p 'root' ssh root@192.168.1.200 "rm -rf /root/Documents/tesi/performance5"
sshpass -p 'root' ssh root@192.168.1.200 "mkdir /root/Documents/tesi/performance5"

sshpass -p 'root' scp clt_setup.sh root@192.168.1.200:/root/Documents/tesi/performance5/clt_setup.sh
sshpass -p 'root' scp run.sh root@192.168.1.200:/root/Documents/tesi/performance5/run.sh

sshpass -p 'root' scp aes256ctr.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp aes256ctr.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp api.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp client.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp config.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp fips202.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp fips202.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp ntt.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp ntt.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp packing.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp packing.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp parameters.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp params.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp poly.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp poly.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp polyvec.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp polyvec.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp PQCgenKAT_sign.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp randombytes.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp randombytes.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp reduce.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp reduce.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp rng.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp rng.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp rounding.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp rounding.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp shared.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp shared.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp sign.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp sign.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp symmetric.h root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp symmetric-aes.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp symmetric-shake.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp test_dilithium.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp util.c root@192.168.1.200:/root/Documents/tesi/performance5
sshpass -p 'root' scp util.h root@192.168.1.200:/root/Documents/tesi/performance5

sshpass -p 'root' scp makefile.clt root@192.168.1.200:/root/Documents/tesi/performance5/makefile.clt
sshpass -p 'root' ssh root@192.168.1.200 "chmod +x /root/Documents/tesi/performance5/clt_setup.sh"
sshpass -p 'root' ssh root@192.168.1.200 "/root/Documents/tesi/performance5/clt_setup.sh"

sshpass -p 'root' scp pub_key root@192.168.1.200:/root/Documents/tesi/performance5/Client
wait

rm -f pub_key

<< 'MULTILINE-COMMENT'
MULTILINE-COMMENT

chmod 777 -R .
