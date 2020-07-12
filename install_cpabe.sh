#!/bin/bash
mkdir dependency
cd dependency
apt-get update
apt-get dist-upgrade
apt-get install libssl-dev libboost-all-dev m4 libreadline-dev lzip flex bison libglib2.0-dev #default-jre

wget https://gmplib.org/download/gmp/gmp-6.2.0.tar.lz
lzip -vd gmp-6.2.0.tar.lz
tar -xvf gmp-6.2.0.tar
cd gmp-6.2.0
./configure
make
make install
make check
cd ..
rm -rf gmp-6.2.0.tar 

wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
tar -xvf pbc-0.5.14.tar.gz
cd pbc-0.5.14
./configure
make
make install // QUI VIENE FUORI UN WARNING
make check
cd ..
rm -rf pbc-0.5.14.tar.gz 

wget http://acsc.cs.utexas.edu/cpabe/libbswabe-0.9.tar.gz
tar -xvf libbswabe-0.9.tar.gz
cd libbswabe-0.9
./configure
make
make install
cd ..
rm -rf libbswabe-0.9.tar.gz

wget http://acsc.cs.utexas.edu/cpabe/cpabe-0.11.tar.gz
tar -xvf cpabe-0.11.tar.gz
cd cpabe-0.11
./configure
sed '67s/result: policy { final_policy = $1 }/result: policy { final_policy = $1; }/' policy_lang.y > file.tmp && mv file.tmp policy_lang.y
sed '19s/$/-lgmp/' Makefile > file.tmp && mv file.tmp Makefile
make
make install
cd ..
rm -rf cpabe-0.11.tar.gz

apt-get autoclean
apt-get autoremove