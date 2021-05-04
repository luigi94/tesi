#!/bin/bash
make -f makefile.srv clean
rm -f Server
make -f makefile.srv

cp vim-runtime_2%3a8.1.2269-1ubuntu5_all.deb Server

<< 'MULTILINE-COMMENT'
MULTILINE-COMMENT

chmod 777 -R .
