#!/bin/bash

INPUT=$1
CLT="client_1.c"
SRV="server_1.c"

if [[ $INPUT = 1 ]]
	then
		echo "Configuration for Scenario 1"
elif [[ $INPUT = 2 ]]
	then
		echo "Configuration for Scenario 2"
		CLT="client_2.c"
		SRV="server_2.c"
elif [[ $INPUT = 3 ]]
	then
		echo "Configuration for Scenario 3"
		CLT="client_3.c"
		SRV="server_3.c"
elif [[ $INPUT = 4 ]]
	then
		echo "Configuration for Scenario 4"
		CLT="client_4.c"
		SRV="server_4.c"
else
	echo "Unknown configuration, use default (1)"
	INPUT=1
fi

make clean
make all client=$CLT server=$SRV

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out srvprvkey.pem
openssl pkey -in srvprvkey.pem -pubout -out srvpubkey.pem

mv -f srvprvkey.pem Server
mv -f srvpubkey.pem Client

if [[ $INPUT = 1 ]]
	then
		cp -f to_send.pdf Server
elif [[ $INPUT = 2 ]]
	then
		cpabe-setup
		cpabe-keygen -o kevin_priv_key pub_key master_key business_staff strategy_team 'executive_level = 7' 'office = 2362' 'hire_date = '`date +%s`
    cpabe-enc -k pub_key to_send.pdf '(sysadmin and (hire_date < 946702800 or security_team or prova6)) or (business_staff and 2 of (executive_level >= 5, audit_group, strategy_team, prova1, prova2, prova3))'
		mv -f master_key Server
		cp -f pub_key Server
		mv -f pub_key Client
		mv -f kevin_priv_key Client
		mv -f to_send.pdf.cpabe Server
		
elif [[ $INPUT = 3 ]]
	then
		openssl genrsa -out cltprvkey.pem 3072
		openssl rsa -pubout -in cltprvkey.pem -out cltpubkey.pem
		
		cpabe-setup
		cpabe-keygen -o kevin_priv_key pub_key master_key business_staff strategy_team 'executive_level = 7' 'office = 2362' 'hire_date = '`date +%s`
    cpabe-enc -k pub_key to_send.pdf '(sysadmin and (hire_date < 946702800 or security_team or prova6)) or (business_staff and 2 of (executive_level >= 5, audit_group, strategy_team, prova1, prova2, prova3))'
		
		mv -f cltpubkey.pem Server
		mv -f cltprvkey.pem Client
		mv -f master_key Server
		cp -f pub_key Server
		mv -f pub_key Client
		cp -f kevin_priv_key Server
		mv -f kevin_priv_key Client
		mv -f to_send.pdf.cpabe Server
elif [[ $INPUT = 4 ]]
	then
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

		#cpabe-updatecp to_send.pdf.cpabe upd_key pub_key
fi

chmod 777 -R .

<< 'MULTILINE-COMMENT'
cpabe-update-partial-updates partial_updates upd_key pub_key
cpabe-update-pub-and-prv-partial partial_updates pub_key kevin_priv_key


cpabe-updatecp to_send.pdf upd_key pub_key
cpabe-updatecp to_send.pdf upd_key pub_key

cpabe-dec pub_key kevin_priv_key to_send.pdf
MULTILINE-COMMENT
