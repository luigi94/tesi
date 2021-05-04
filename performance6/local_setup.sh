#!/bin/bash
make -f makefile.srv clean
make -f makefile.srv all

cp -f linux-libc-dev_5.4.0-70.78_arm64.deb Server

chmod 777 -R .
