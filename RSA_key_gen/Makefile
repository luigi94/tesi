CC = gcc

all: rsa_key_gen

rsa_key_gen: rsa_key_gen.c
	$(CC) -Wall -Wextra -O3 rsa_key_gen.c -o $@ -lcrypto
	
clean:
	rm -f rsa_key_gen
