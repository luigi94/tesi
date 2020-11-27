#!/bin/bash
rm -f upd_key

seabrew-abe-setup

seabrew-abe-keygen -o sara_priv_key -p dummy pub_key master_key \
    sysadmin it_department 'office = 1431'

seabrew-abe-keygen -o kevin_priv_key pub_key master_key \
    business_staff strategy_team 'executive_level = 7' \
    'office = 2362'
    
seabrew-abe-updatemk pub_key master_key upd_key
seabrew-abe-updatemk pub_key master_key upd_key
seabrew-abe-updatemk pub_key master_key upd_key
seabrew-abe-updatemk pub_key master_key upd_key
    
seabrew-abe-update-partial-updates partial_updates upd_key pub_key
seabrew-abe-update-pub-and-prv-partial partial_updates pub_key kevin_priv_key
    
seabrew-abe-updatemk pub_key master_key upd_key
seabrew-abe-updatemk pub_key master_key upd_key
seabrew-abe-updatemk pub_key master_key upd_key
seabrew-abe-updatemk pub_key master_key upd_key

seabrew-abe-update-partial-updates partial_updates upd_key pub_key
seabrew-abe-update-pub-and-prv-partial partial_updates pub_key kevin_priv_key
    
seabrew-abe-enc -k pub_key to_send.pdf '(sysadmin and (hire_date < 946702800 or security_team or prova6)) or (business_staff and 2 of (executive_level >= 5, audit_group, strategy_team, prova1, prova2, prova3))'


seabrew-abe-updatemk pub_key master_key upd_key
seabrew-abe-updatemk pub_key master_key upd_key
seabrew-abe-updatemk pub_key master_key upd_key
seabrew-abe-updatemk pub_key master_key upd_key

seabrew-abe-update-partial-updates partial_updates upd_key pub_key
seabrew-abe-update-pub-and-prv-partial partial_updates pub_key kevin_priv_key

#cpabe-updatepk pub_key upd_key

#cpabe-updatedk kevin_priv_key upd_key pub_key

seabrew-abe-updatecp to_send.pdf.cpabe upd_key pub_key
seabrew-abe-updatecp to_send.pdf.cpabe upd_key pub_key

seabrew-abe-dec pub_key kevin_priv_key to_send.pdf.cpabe -o decrypted.pdf

<< 'MULTILINE-COMMENT'

cpabe-updatemk pub_key master_key upd_key

cpabe-updatepk pub_key upd_key

cpabe-updatemk pub_key master_key upd_key

cpabe-updatepk pub_key upd_key

cpabe-updatedk kevin_priv_key upd_key pub_key

cpabe-updatecp document.txt.cpabe upd_key pub_key
cpabe-updatecp document.txt.cpabe upd_key pub_key

MULTILINE-COMMENT
chmod 777 -R .
echo "END"
