#!/bin/bash
cd /root/Documents/tesi/performance6
make -f makefile.clt clean
make -f makefile.clt all

rm -f *.o

chmod 777 -R .
