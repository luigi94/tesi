#!/bin/bash
if [ -z "$1" ] || [ "$#" -ne 1 ]
then
	echo "USAGE ./ec_key_gen.sh CURVE"
	exit
fi

#prime256v1 for 128-bit security
#secp384r1 for 192-bit security
#secp521r1 for 256-bit securiy (actually a little more)
rm -rf "$1_bits_keys"
mkdir -p "$1_bits_keys"

for i in {101..500}
do
	openssl ecparam -genkey -name $1 -out "$1_bits_keys/srvprvkey$i.pem"
	
	openssl ec -pubout -in "$1_bits_keys/srvprvkey$i.pem" -out "$1_bits_keys/srvpubkey$i.pem"
done
chmod 777 -R *
