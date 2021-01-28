#!/bin/bash

cd libseabrew-0.1/ && make clean && make && make install
cd ./../seabrew-abe-0.1/ && make clean && make && make install
cd ./../ && seabrew-abe-print-upd upd_key pub_key 
