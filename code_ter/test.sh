#!/bin/bash
rm master_key pub_key upd_key
cd libbswabe-0.9
make clean
./configure
make
make install
cd ..

cd cpabe-0.11
make clean
./configure
#sed '67s/result: policy { final_policy = $1 }/result: policy { final_policy = $1; }/' policy_lang.y > file.tmp && mv file.tmp policy_lang.y
#sed '19s/$/-lgmp/' Makefile > file.tmp && mv file.tmp Makefile
make
make install
cd ..

rm -r document.*
touch document.txt
echo "COSE SEGRETE" > document.txt
chmod 777 document.txt

cpabe-setup -d

cpabe-keygen -d -o sara_priv_key -p dummy pub_key master_key \
    sysadmin it_department 'office = 1431' 'hire_date = '`date +%s`

cpabe-keygen -d -o kevin_priv_key pub_key master_key \
    business_staff strategy_team 'executive_level = 7' \
    'office = 2362' 'hire_date = '`date +%s`
    
cpabe-enc -d pub_key document.txt '(sysadmin and (hire_date < 946702800 or security_team or prova6)) or (business_staff and 2 of (executive_level >= 5, audit_group, strategy_team, prova1, prova2, prova3))'

echo "---"
cpabe-print pub pub_key 
cpabe-print prv kevin_priv_key pub_key 
cpabe-print partial partial_updates pub_key 
echo "---"

cpabe-updatemk -d pub_key master_key upd_key
cpabe-update-partial-updates partial_updates upd_key pub_key

echo "---"
cpabe-print pub pub_key 
cpabe-print prv kevin_priv_key pub_key 
cpabe-print partial partial_updates pub_key 
echo "---"

cpabe-update-pub-and-prv-partial partial_updates pub_key kevin_priv_key

cpabe-updatecp document.txt.cpabe upd_key pub_key

cpabe-dec -d pub_key kevin_priv_key document.txt.cpabe
<< 'MULTILINE-COMMENT'
MULTILINE-COMMENT
chmod 777 -R .
echo "END"

