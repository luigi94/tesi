#!/bin/bash
make -f makefile.srv clean
make -f makefile.srv all

./key_gen

mv -f prv_key Server
mv -f pub_key Client

cp secret.txt Server

<< 'MULTILINE-COMMENT'
MULTILINE-COMMENT

chmod 777 -R .
