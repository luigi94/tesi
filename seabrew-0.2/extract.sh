#!/bin/bash
rm -f dummy kevin_priv_key master_key partial_updates pub_key sara_priv_key upd_key decrypted.pdf to_send.pdf.cpabe u_cp u_dk u_pk extracted
seabrew-abe-setup
seabrew-abe-updatemk pub_key master_key upd_key -s 101
seabrew-abe-updatemk pub_key master_key upd_key -s 102
seabrew-abe-updatemk pub_key master_key upd_key -s 103
seabrew-abe-updatemk pub_key master_key upd_key -s 104
seabrew-abe-updatemk pub_key master_key upd_key -s 105
seabrew-abe-updatemk pub_key master_key upd_key -s 106
seabrew-abe-updatemk pub_key master_key upd_key -s 107
seabrew-abe-updatemk pub_key master_key upd_key -s 108
seabrew-abe-updatemk pub_key master_key upd_key -s 109
seabrew-abe-updatemk pub_key master_key upd_key -s 110
seabrew-abe-updatemk pub_key master_key upd_key -s 111
seabrew-abe-updatemk pub_key master_key upd_key -s 112

seabrew-abe-extract upd_key pub_key extracted -s 1 -e 1
seabrew-abe-print-upd extracted pub_key
echo "STEP"
seabrew-abe-extract upd_key pub_key extracted -s 2 -e 2
seabrew-abe-print-upd extracted pub_key
echo "STEP"
seabrew-abe-extract upd_key pub_key extracted -s 3 -e 3
seabrew-abe-print-upd extracted pub_key
echo "STEP"
seabrew-abe-extract upd_key pub_key extracted -s 4 -e 4
seabrew-abe-print-upd extracted pub_key
echo "STEP"
seabrew-abe-extract upd_key pub_key extracted -s 5 -e 5
seabrew-abe-print-upd extracted pub_key
echo "STEP"
seabrew-abe-extract upd_key pub_key extracted -s 6 -e 6
seabrew-abe-print-upd extracted pub_key
echo "STEP"
seabrew-abe-extract upd_key pub_key extracted -s 7 -e 7
seabrew-abe-print-upd extracted pub_key
echo "STEP"
seabrew-abe-extract upd_key pub_key extracted -s 8 -e 8
seabrew-abe-print-upd extracted pub_key
echo "STEP"
seabrew-abe-extract upd_key pub_key extracted -s 9 -e 9
seabrew-abe-print-upd extracted pub_key
echo "STEP"
seabrew-abe-extract upd_key pub_key extracted -s 10 -e 10
seabrew-abe-print-upd extracted pub_key
echo "STEP"
seabrew-abe-extract upd_key pub_key extracted -s 11 -e 11
seabrew-abe-print-upd extracted pub_key
echo "STEP"
seabrew-abe-extract upd_key pub_key	 extracted -s 12 -e 12
seabrew-abe-print-upd extracted pub_key
seabrew-abe-print-upd upd_key pub_key
echo "STEP"
