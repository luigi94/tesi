#!/bin/bash
make clean
make all

#sshpass -p 'root' ssh root@192.168.1.200 "mkdir -p /root/Documents/tesi/performance/Client"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out srvprvkey.pem
openssl pkey -in srvprvkey.pem -pubout -out srvpubkey.pem

cpabe-setup

cpabe-keygen -o kevin_priv_key pub_key master_key business_staff strategy_team 'executive_level = 7' 'office = 2362' 'hire_date = '`date +%s`
cpabe-enc -k pub_key to_send.pdf '(sysadmin and (hire_date < 946702800 or security_team or prova6)) or (business_staff and 2 of (executive_level >= 5, audit_group, strategy_team, prova1, prova2, prova3))'

openssl genrsa -out cltprvkey.pem 3072
openssl rsa -pubout -in cltprvkey.pem -out cltpubkey.pem

cp -f srvprvkey.pem Server_1
cp -f srvprvkey.pem Server_2
cp -f srvprvkey.pem Server_3
cp -f srvprvkey.pem Server_4
cp -f srvpubkey.pem Client_1
cp -f srvpubkey.pem Client_2
cp -f srvpubkey.pem Client_3
mv -f srvpubkey.pem Client_4
#sshpass -p 'root' scp srvpubkey.pem root@192.168.1.200:/root/Documents/tesi/performance/Client

cp -f to_send.pdf Server_1
cp -f to_send.pdf Server_3

cp -f master_key Server_2
cp -f master_key Server_3

cp -f pub_key Server_2
cp -f pub_key Server_3
cp -f pub_key Client_2
cp -f pub_key Client_3

#sshpass -p 'root' scp pub_key root@192.168.1.200:/root/Documents/tesi/performance/Client
#sshpass -p 'root' scp kevin_priv_key root@192.168.1.200:/root/Documents/tesi/performance/Client

cp -f kevin_priv_key Client_2
cp -f kevin_priv_key Client_3
cp -f kevin_priv_key Client_4
cp -f to_send.pdf.cpabe Server_2
cp -f to_send.pdf.cpabe Server_4
		
cp -f cltpubkey.pem Server_3
#sshpass -p 'root' scp cltprvkey.pem root@192.168.1.200:/root/Documents/tesi/performance/Client
cp -f cltprvkey.pem Client_3
#sshpass -p 'root' scp pub_key root@192.168.1.200:/root/Documents/tesi/performance/Client


cpabe-updatemk pub_key master_key upd_key
cpabe-updatemk pub_key master_key upd_key
cpabe-updatemk pub_key master_key upd_key
cpabe-updatemk pub_key master_key upd_key

cp -f master_key Server_4
cp -f pub_key Server_4
cp -f master_key Client_4
cp -f pub_key Client_4
#sshpass -p 'root' scp pub_key root@192.168.1.200:/root/Documents/tesi/performance/Client
#sshpass -p 'root' scp kevin_priv_key root@192.168.1.200:/root/Documents/tesi/performance/Client
cp -f partial_updates Server_4
cp -f upd_key Server_4

rm -f cltprvkey.pem
rm -f cltpubkey.pem
rm -f kevin_priv_key
rm -f master_key
rm -f partial_updates
rm -f pub_key
rm -f srvprvkey.pem
rm -f to_send.pdf.cpabe
rm -f upd_key

chmod 777 -R .
