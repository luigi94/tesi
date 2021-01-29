#!/bin/bash
rm -f upd_key u_dk u_cp extracted
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

seabrew-abe-extract upd_key pub_key -o extracted -s 1 -e 1
seabrew-abe-extract-u-dk extracted pub_key u_dk
seabrew-abe-extract-u-cp extracted pub_key u_cp
echo "STEP"
seabrew-abe-extract upd_key pub_key -o extracted -s 2 -e 2
seabrew-abe-extract-u-dk extracted pub_key u_dk
seabrew-abe-extract-u-cp extracted pub_key u_cp
echo "STEP"
seabrew-abe-extract upd_key pub_key -o extracted -s 3 -e 3
seabrew-abe-extract-u-dk extracted pub_key u_dk
seabrew-abe-extract-u-cp extracted pub_key u_cp
echo "STEP"
seabrew-abe-extract upd_key pub_key -o extracted -s 4 -e 4
seabrew-abe-extract-u-dk extracted pub_key u_dk
seabrew-abe-extract-u-cp extracted pub_key u_cp
echo "STEP"
seabrew-abe-extract upd_key pub_key -o extracted -s 5 -e 5
seabrew-abe-extract-u-dk extracted pub_key u_dk
seabrew-abe-extract-u-cp extracted pub_key u_cp
echo "STEP"
seabrew-abe-extract upd_key pub_key -o extracted -s 6 -e 6
seabrew-abe-extract-u-dk extracted pub_key u_dk
seabrew-abe-extract-u-cp extracted pub_key u_cp
echo "STEP"
seabrew-abe-extract upd_key pub_key -o extracted -s 7 -e 7
seabrew-abe-extract-u-dk extracted pub_key u_dk
seabrew-abe-extract-u-cp extracted pub_key u_cp
echo "STEP"
seabrew-abe-extract upd_key pub_key -o extracted -s 8 -e 8
seabrew-abe-extract-u-dk extracted pub_key u_dk
seabrew-abe-extract-u-cp extracted pub_key u_cp
echo "STEP"
seabrew-abe-extract upd_key pub_key -o extracted -s 9 -e 9
seabrew-abe-extract-u-dk extracted pub_key u_dk
seabrew-abe-extract-u-cp extracted pub_key u_cp
echo "STEP"
seabrew-abe-extract upd_key pub_key -o extracted -s 10 -e 10
seabrew-abe-extract-u-dk extracted pub_key u_dk
seabrew-abe-extract-u-cp extracted pub_key u_cp
echo "STEP"
seabrew-abe-extract upd_key pub_key -o extracted -s 11 -e 11
seabrew-abe-extract-u-dk extracted pub_key u_dk
seabrew-abe-extract-u-cp extracted pub_key u_cp
echo "STEP"
seabrew-abe-extract upd_key pub_key -o extracted -s 12 -e 12
seabrew-abe-extract-u-dk extracted pub_key u_dk
seabrew-abe-extract-u-cp extracted pub_key u_cp
echo "STEP"
openssl md5 u_cp
openssl md5 u_dk
