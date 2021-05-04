#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "randombytes.h"
#include "sign.h"

#define MLEN 59
#define NTESTS 10000

char* plaintext_file = "vim-runtime_2\%3a8.1.2269-1ubuntu5_all.deb";

int main(void){
  size_t i, j;
  int ret;
  size_t mlen, smlen;
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  
	unsigned char* m;
	unsigned char* m2;
	unsigned char* sm;
	
	size_t plaintext_len;
	FILE* f_plaintext;
	
	if((f_plaintext = fopen(plaintext_file, "r")) == NULL){
		fprintf(stderr, "Error in opening %s. Error: %s\n", plaintext_file, strerror(errno));
		exit(1);
	}
	
	fseek(f_plaintext, 0UL, SEEK_END);
	plaintext_len = ftell(f_plaintext);
	rewind(f_plaintext);
	
	if((m = (unsigned char*)malloc((size_t)(plaintext_len + CRYPTO_BYTES))) == NULL){
		fprintf(stderr, "Error in allocating memory for m. Error: %s\n", strerror(errno));
		exit(1);
	}
	
	if(fread((void*)m, 1UL, plaintext_len, f_plaintext) < plaintext_len){
		fprintf(stderr, "Error while reading file '%s'. Error: %s\n", plaintext_file, strerror(errno));
		exit(1);
	}
	fclose(f_plaintext);
	
	if((m2 = (unsigned char*)malloc((size_t)(plaintext_len + CRYPTO_BYTES))) == NULL){
		fprintf(stderr, "Error in allocating memory for m2. Error: %s\n", strerror(errno));
		exit(1);
	}
	if((sm = (unsigned char*)malloc((size_t)(plaintext_len + CRYPTO_BYTES))) == NULL){
		fprintf(stderr, "Error in allocating memory for sm. Error: %s\n", strerror(errno));
		exit(1);
	}
	
  for(i = 0; i < NTESTS; ++i) {

    crypto_sign_keypair(pk, sk);
    crypto_sign(sm, &smlen, m, MLEN, sk);
    ret = crypto_sign_open(m2, &mlen, sm, smlen, pk);

    if(ret) {
      fprintf(stderr, "Verification failed\n");
      return -1;
    }
    if(smlen != MLEN + CRYPTO_BYTES) {
      fprintf(stderr, "Signed message lengths wrong\n");
      return -1;
    }
    if(mlen != MLEN) {
      fprintf(stderr, "Message lengths wrong\n");
      return -1;
    }
    for(j = 0; j < MLEN; ++j) {
      if(m2[j] != m[j]) {
        fprintf(stderr, "Messages don't match\n");
        return -1;
      }
    }
  }

  printf("CRYPTO_PUBLICKEYBYTES = %d\n", CRYPTO_PUBLICKEYBYTES);
  printf("CRYPTO_SECRETKEYBYTES = %d\n", CRYPTO_SECRETKEYBYTES);
  printf("CRYPTO_BYTES = %d\n", CRYPTO_BYTES);

  return 0;
}
