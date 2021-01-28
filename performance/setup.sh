#!/bin/bash
make -f makefile.srv clean
make -f makefile.srv all

sshpass -p 'root' scp makefile.clt root@192.168.1.200:/root/Documents/tesi/performance/makefile.clt
sshpass -p 'root' scp src/client_4.c root@192.168.1.200:/root/Documents/tesi/performance/src/client_4.c
sshpass -p 'root' scp src/common.c root@192.168.1.200:/root/Documents/tesi/performance/src/common.c
sshpass -p 'root' scp src/common.h root@192.168.1.200:/root/Documents/tesi/performance/src/common.h
sshpass -p 'root' scp src/core.c root@192.168.1.200:/root/Documents/tesi/performance/src/core.c
sshpass -p 'root' scp src/cpabe.h root@192.168.1.200:/root/Documents/tesi/performance/src/cpabe.h
sshpass -p 'root' scp src/shared.c root@192.168.1.200:/root/Documents/tesi/performance/src/shared.c
sshpass -p 'root' scp src/shared.h root@192.168.1.200:/root/Documents/tesi/performance/src/shared.h
sshpass -p 'root' scp src/misc.c root@192.168.1.200:/root/Documents/tesi/performance/src/misc.c
sshpass -p 'root' scp src/parameters.h root@192.168.1.200:/root/Documents/tesi/performance/src/parameters.h
sshpass -p 'root' scp src/private.h root@192.168.1.200:/root/Documents/tesi/performance/src/private.h
sshpass -p 'root' scp src/util.c root@192.168.1.200:/root/Documents/tesi/performance/src/util.c
sshpass -p 'root' scp src/util.h root@192.168.1.200:/root/Documents/tesi/performance/src/util.h
sshpass -p 'root' scp clt_setup.sh root@192.168.1.200:/root/Documents/tesi/performance/clt_setup.sh
sshpass -p 'root' scp run.sh root@192.168.1.200:/root/Documents/tesi/performance/run.sh
sshpass -p 'root' ssh root@192.168.1.200 "chmod +x /root/Documents/tesi/performance/clt_setup.sh"
sshpass -p 'root' ssh root@192.168.1.200 "/root/Documents/tesi/performance/clt_setup.sh"
wait

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out srvprvkey.pem
openssl pkey -in srvprvkey.pem -pubout -out srvpubkey.pem

seabrew-abe-setup

seabrew-abe-keygen -o blue_vehicle_priv_key -p blue_vehicle_partial_updates pub_key master_key CAR_MODEL_23 ECU_MODEL_2247 ECU_MODEL_2256 ECU_MODEL_2268
seabrew-abe-keygen -o green_vehicle_priv_key -p green_vehicle_partial_updates pub_key master_key CAR_MODEL_21 ECU_MODEL_2246 ECU_MODEL_2248
seabrew-abe-enc -k pub_key vim-runtime_2%3a8.1.2269-1ubuntu5_all.deb 'ECU_MODEL_2247 or (CAR_MODEL_21 and ECU_MODEL_2248)'

openssl genrsa -out cltprvkey.pem 3072
openssl rsa -pubout -in cltprvkey.pem -out cltpubkey.pem

cp -f srvprvkey.pem Server_4
cp -f srvpubkey.pem Client_4
sshpass -p 'root' scp srvpubkey.pem root@192.168.1.200:/root/Documents/tesi/performance/Client_4

cp -f blue_vehicle_priv_key Client_4
cp -f green_vehicle_priv_key Client_4
cp -f blue_vehicle_partial_updates Server_4
cp -f green_vehicle_partial_updates Server_4
sshpass -p 'root' scp blue_vehicle_priv_key root@192.168.1.200:/root/Documents/tesi/performance/Client_4
sshpass -p 'root' scp green_vehicle_priv_key root@192.168.1.200:/root/Documents/tesi/performance/Client_4
sshpass -p 'root' scp blue_vehicle_partial_updates root@192.168.1.200:/root/Documents/tesi/performance/Server_4
sshpass -p 'root' scp green_vehicle_partial_updates root@192.168.1.200:/root/Documents/tesi/performance/Server_4

cp -f vim-runtime_2%3a8.1.2269-1ubuntu5_all.deb.cpabe Server_4

cp -f master_key Server_4
cp -f pub_key Server_4
cp -f pub_key Client_4
sshpass -p 'root' scp pub_key root@192.168.1.200:/root/Documents/tesi/performance/Client_4
#cp -f upd_key Server_4

rm -f cltprvkey.pem
rm -f cltpubkey.pem
rm -f blue_vehicle_priv_key
rm -f green_vehicle_priv_key
rm -f blue_vehicle_partial_updates
rm -f green_vehicle_partial_updates
rm -f master_key
rm -f pub_key
rm -f srvprvkey.pem
rm -rf srvpubkey.pem
rm -f vim-runtime_2%3a8.1.2269-1ubuntu5_all.deb.cpabe
rm -f upd_key

chmod 777 -R .
