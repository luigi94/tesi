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

cpabe-setup 

cpabe-keygen -o sara_priv_key pub_key master_key \
    sysadmin it_department 'office = 1431' 'hire_date = '`date +%s`

cpabe-keygen -o kevin_priv_key pub_key master_key \
    business_staff strategy_team 'executive_level = 7' \
    'office = 2362' 'hire_date = '`date +%s`
    
cpabe-enc pub_key document.txt '(sysadmin and (hire_date < 946702800 or security_team or prova6)) or (business_staff and 2 of (executive_level >= 5, audit_group, strategy_team, prova1, prova2, prova3))'

cpabe-updatemk pub_key master_key upd_key
cpabe-updatepk pub_key upd_key

cpabe-updatedk kevin_priv_key upd_key pub_key

cpabe-updatecp document.txt.cpabe upd_key pub_key

cpabe-dec pub_key kevin_priv_key document.txt.cpabe

chmod 777 -R .
<< 'MULTILINE-COMMENT'	
MULTILINE-COMMENT
echo "END"

