#!/bin/bash
echo 1 > /proc/sys/vm/drop_caches
echo 2 > /proc/sys/vm/drop_caches
echo 3 > /proc/sys/vm/drop_caches
make -f makefile.srv clean
make -f makefile.srv all

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out srvprvkey.pem
openssl pkey -in srvprvkey.pem -pubout -out srvpubkey.pem

cpabe-setup

cpabe-keygen -o blue_vehicle_priv_key -p blue_vehicle_partial_updates pub_key master_key CAR_MODEL_23 ECU_MODEL_2247 ECU_MODEL_2256 ECU_MODEL_2268
cpabe-keygen -o green_vehicle_priv_key -p green_vehicle_partial_updates pub_key master_key CAR_MODEL_21 ECU_MODEL_2246 ECU_MODEL_2248
cpabe-enc -k pub_key to_send.pdf 'ECU_MODEL_2247 or (CAR_MODEL_21 and ECU_MODEL_2248)'

openssl genrsa -out cltprvkey.pem 3072
openssl rsa -pubout -in cltprvkey.pem -out cltpubkey.pem

cp -f srvprvkey.pem Server_1
cp -f srvprvkey.pem Server_2
cp -f srvprvkey.pem Server_3
cp -f srvprvkey.pem Server_4
cp -f srvpubkey.pem Client_1
cp -f srvpubkey.pem Client_2
cp -f srvpubkey.pem Client_3
cp -f srvpubkey.pem Client_4

cp -f to_send.pdf Server_1
cp -f to_send.pdf Server_3

cp -f master_key Server_2
cp -f master_key Server_3

cp -f pub_key Server_2
cp -f pub_key Server_3
cp -f pub_key Client_2
cp -f pub_key Client_3

cp -f blue_vehicle_priv_key Client_2
cp -f blue_vehicle_priv_key Client_4
cp -f green_vehicle_priv_key Client_2
cp -f green_vehicle_priv_key Client_4

cp -f to_send.pdf.cpabe Server_2
cp -f to_send.pdf.cpabe Server_4
		
cp -f cltpubkey.pem Server_3
cp -f cltprvkey.pem Client_3

cpabe-updatemk pub_key master_key upd_key
cpabe-updatemk pub_key master_key upd_key
cpabe-updatemk pub_key master_key upd_key
cpabe-updatemk pub_key master_key upd_key

cp -f master_key Server_4
cp -f pub_key Server_4
cp -f pub_key Client_4
cp -f blue_vehicle_partial_updates Server_4
cp -f green_vehicle_partial_updates Server_4
cp -f upd_key Server_4

rm -f cltprvkey.pem
rm -f cltpubkey.pem
rm -f blue_vehicle_priv_key
rm -f green_vehicle_priv_key
rm -f master_key
rm -f blue_vehicle_partial_updates
rm -f green_vehicle_partial_updates
rm -f pub_key
rm -f srvprvkey.pem
rm -rf srvpubkey.pem
rm -f to_send.pdf.cpabe
rm -f upd_key

chmod 777 -R .
