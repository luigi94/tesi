#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "randombytes.h"
#include "sign.h"

char* public_key_name = "pub_key";
char* private_key_name = "prv_key";

void write_file(const unsigned char* const restrict buffer, const size_t data_len, const char* const restrict name);

int main(void){
	
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];

  crypto_sign_keypair(pk, sk);
  
  write_file((unsigned char*)pk, CRYPTO_PUBLICKEYBYTES, public_key_name);
  write_file((unsigned char*)sk, CRYPTO_SECRETKEYBYTES, private_key_name);
  
  return 0;
}

void write_file(const unsigned char* const restrict buffer, const size_t data_len, const char* const restrict name){
	FILE* tmp;
	if((tmp = fopen(name, "w")) == NULL){
		fprintf(stderr, "Error in opening %s. Error: %s\n", name, strerror(errno));
		exit(1);
	}
	if(fwrite(buffer, data_len, 1UL, tmp) != 1UL){
		fprintf(stderr, "Error in writing %s. Error: %s\n", name, strerror(errno));
		fclose(tmp);
		exit(1);
	}
	fclose(tmp);
}
