#!/bin/bash
if [ -z "$1" ] || [ "$#" -ne 1 ]
then
	echo "USAGE ./rsa_key_gen.sh MODULUS"
	exit
fi

rm -rf "$1_bits_keys"
mkdir -p "$1_bits_keys"

for i in {101..500}
do
	echo "Iteration $i" 
	openssl genrsa -out "$1_bits_keys/srvprvkey$i.pem" $1
	openssl rsa -in "$1_bits_keys/srvprvkey$i.pem" -outform PEM -pubout -out "$1_bits_keys/srvpubkey$i.pem"
done
chmod 777 -R *
