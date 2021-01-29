#!/bin/bash
rm -f dummy kevin_priv_key master_key partial_updates pub_key sara_priv_key upd_key decrypted.pdf to_send.pdf.cpabe u_cp u_dk u_pk extracted

seabrew-abe-setup

seabrew-abe-enc -k pub_key to_send.pdf '(sysadmin and (hire_date < 946702800 or security_team or prova6)) or (business_staff and 2 of (executive_level >= 5, audit_group, strategy_team, prova1, prova2, prova3))'

seabrew-abe-keygen -o sara_priv_key pub_key master_key \
    sysadmin it_department 'office = 1431'

seabrew-abe-keygen -o kevin_priv_key pub_key master_key \
    business_staff strategy_team 'executive_level = 7' \
    'office = 2362'

seabrew-abe-updatemk pub_key master_key upd_key -s 3256    
seabrew-abe-updatemk pub_key master_key upd_key -s 3205
seabrew-abe-updatemk pub_key master_key upd_key -s 3206
seabrew-abe-update-d kevin_priv_key.d upd_key pub_key
seabrew-abe-updatecp to_send.pdf.cpabe upd_key pub_key
seabrew-abe-updatedk kevin_priv_key kevin_priv_key.d pub_key


seabrew-abe-updatemk pub_key master_key upd_key -s 21245
seabrew-abe-update-d kevin_priv_key.d upd_key pub_key
seabrew-abe-updatecp to_send.pdf.cpabe upd_key pub_key
seabrew-abe-updatedk kevin_priv_key kevin_priv_key.d pub_key

seabrew-abe-updatemk pub_key master_key upd_key -s 21245
seabrew-abe-update-d kevin_priv_key.d upd_key pub_key
seabrew-abe-updatecp to_send.pdf.cpabe upd_key pub_key
seabrew-abe-updatedk kevin_priv_key kevin_priv_key.d pub_key

seabrew-abe-dec -k pub_key kevin_priv_key to_send.pdf.cpabe -o decrypted.pdf

openssl md5 to_send.pdf
openssl md5 decrypted.pdf

<< 'MULTILINE-COMMENT'
seabrew-abe-extract-u-pk upd_key pub_key u_pk
seabrew-abe-updatepk pub_key u_pk
MULTILINE-COMMENT
