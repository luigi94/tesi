#!/bin/bash

rm ciao
rm extracted
seabrew-abe-extract upd_key pub_key -o extracted -s 1 -e 12
seabrew-abe-extract-u-dk extracted pub_key ciao
echo "STEP"
seabrew-abe-extract upd_key pub_key -o extracted -s 2 -e 2
seabrew-abe-extract-u-dk extracted pub_key ciao
echo "STEP"
seabrew-abe-extract upd_key pub_key -o extracted -s 3 -e 3
seabrew-abe-extract-u-dk extracted pub_key ciao
echo "STEP"
seabrew-abe-extract upd_key pub_key -o extracted -s 4 -e 4
seabrew-abe-extract-u-dk extracted pub_key ciao
echo "STEP"
seabrew-abe-extract upd_key pub_key -o extracted -s 5 -e 5
seabrew-abe-extract-u-dk extracted pub_key ciao
echo "STEP"
seabrew-abe-extract upd_key pub_key -o extracted -s 6 -e 6
seabrew-abe-extract-u-dk extracted pub_key ciao
echo "STEP"
seabrew-abe-extract upd_key pub_key -o extracted -s 7 -e 7
seabrew-abe-extract-u-dk extracted pub_key ciao
echo "STEP"
seabrew-abe-extract upd_key pub_key -o extracted -s 8 -e 8
seabrew-abe-extract-u-dk extracted pub_key ciao
echo "STEP"
seabrew-abe-extract upd_key pub_key -o extracted -s 9 -e 9
seabrew-abe-extract-u-dk extracted pub_key ciao
echo "STEP"
seabrew-abe-extract upd_key pub_key -o extracted -s 10 -e 10
seabrew-abe-extract-u-dk extracted pub_key ciao
echo "STEP"
seabrew-abe-extract upd_key pub_key -o extracted -s 11 -e 11
seabrew-abe-extract-u-dk extracted pub_key ciao
echo "STEP"
seabrew-abe-extract upd_key pub_key -o extracted -s 12 -e 12
seabrew-abe-extract-u-dk extracted pub_key ciao
echo "STEP"
openssl md5 ciao
