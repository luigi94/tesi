#!/bin/bash
cd /root/Documents/tesi/performance
make -f makefile.clt clean
make -f makefile.clt all

chmod 777 -R .
