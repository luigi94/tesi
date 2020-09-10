#!/bin/bash
rm -rf Client/* Server/*
make clean
make all

cpabe-setup

#cpabe-keygen -o sara_priv_key -p dummy pub_key master_key sysadmin it_department 'office = 1431' 'hire_date = '`date +%s`

cpabe-keygen -o kevin_priv_key pub_key master_key business_staff strategy_team 'executive_level = 7' 'office = 2362' 'hire_date = '`date +%s`
    
cpabe-enc -k pub_key to_send.pdf '(sysadmin and (hire_date < 946702800 or security_team or prova6)) or (business_staff and 2 of (executive_level >= 5, audit_group, strategy_team, prova1, prova2, prova3))'

cpabe-updatemk pub_key master_key upd_key
cpabe-updatemk pub_key master_key upd_key
cpabe-updatemk pub_key master_key upd_key
cpabe-updatemk pub_key master_key upd_key

cp master_key Server
cp pub_key Server
cp pub_key Client
rm master_key pub_key

cp kevin_priv_key Client
cp partial_updates Server
rm kevin_priv_key
rm partial_updates

cp to_send.pdf.cpabe Server
rm to_send.pdf.cpabe

cp upd_key Server
rm upd_key

#cpabe-updatecp to_send.pdf.cpabe upd_key pub_key

chmod 777 -R .

<< 'MULTILINE-COMMENT'
cpabe-update-partial-updates partial_updates upd_key pub_key
cpabe-update-pub-and-prv-partial partial_updates pub_key kevin_priv_key


cpabe-updatecp to_send.pdf upd_key pub_key
cpabe-updatecp to_send.pdf upd_key pub_key

cpabe-dec pub_key kevin_priv_key to_send.pdf
MULTILINE-COMMENT
