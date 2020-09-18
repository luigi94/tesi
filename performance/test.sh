#!/bin/bash
rm -rf Client/* Server/*
make clean
make all

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out srvprvkey.pem
openssl pkey -in srvprvkey.pem -pubout -out srvpubkey.pem

cpabe-setup

#cpabe-keygen -o sara_priv_key -p dummy pub_key master_key sysadmin it_department 'office = 1431' 'hire_date = '`date +%s`

cpabe-keygen -o kevin_priv_key pub_key master_key business_staff strategy_team 'executive_level = 7' 'office = 2362' 'hire_date = '`date +%s`
    
cpabe-enc -k pub_key to_send.pdf '(sysadmin and (hire_date < 946702800 or security_team or prova6)) or (business_staff and 2 of (executive_level >= 5, audit_group, strategy_team, prova1, prova2, prova3))'

cpabe-updatemk pub_key master_key upd_key
cpabe-updatemk pub_key master_key upd_key
cpabe-updatemk pub_key master_key upd_key
cpabe-updatemk pub_key master_key upd_key

mv -f master_key Server
cp -f pub_key Server
mv -f pub_key Client
mv -f kevin_priv_key Client
mv -f partial_updates Server
mv -f to_send.pdf.cpabe Server
mv -f upd_key Server
mv -f srvprvkey.pem Server
cp -f srvpubkey.pem Server
mv -f srvpubkey.pem Client

#cpabe-updatecp to_send.pdf.cpabe upd_key pub_key

chmod 777 -R .

<< 'MULTILINE-COMMENT'
cpabe-update-partial-updates partial_updates upd_key pub_key
cpabe-update-pub-and-prv-partial partial_updates pub_key kevin_priv_key


cpabe-updatecp to_send.pdf upd_key pub_key
cpabe-updatecp to_send.pdf upd_key pub_key

cpabe-dec pub_key kevin_priv_key to_send.pdf
MULTILINE-COMMENT
