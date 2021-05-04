#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include "randombytes.h"
#include "sign.h"

#define PUBLIC_KEY_NAME_PREFIX "srvpubkey%u"
#define PRIVATE_KEY_NAME_PREFIX "srvprvkey%u"
#if DILITHIUM_MODE == 2
#define FOLDER "DILITHIUM2_AES_keys"
#elif DILITHIUM_MODE == 3
#define FOLDER "DILITHIUM3_AES_keys"
#elif DILITHIUM_MODE == 5
#define FOLDER "DILITHIUM5_AES_keys"
#endif
#define KEY_NAME_LEN 32UL
#define NUM 500U

void write_file(const unsigned char* const restrict buffer, const size_t data_len, const char* const restrict folder, const char* const restrict name);
struct stat st = {0};

int main(void){

	char public_key_name[KEY_NAME_LEN];
	char private_key_name[KEY_NAME_LEN];	
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  
	if (stat(FOLDER, &st) == -1) {
		  mkdir(FOLDER, 7777);
	}
  
	for (unsigned i = 1U; i <= NUM; i++) {
	
		crypto_sign_keypair(pk, sk);
		
		snprintf(public_key_name, KEY_NAME_LEN, PUBLIC_KEY_NAME_PREFIX, i);
		snprintf(private_key_name, KEY_NAME_LEN, PRIVATE_KEY_NAME_PREFIX, i);
		fprintf(stdout, "Generating %s and %s\n", public_key_name, private_key_name);
		
		write_file((unsigned char*)pk, CRYPTO_PUBLICKEYBYTES, FOLDER, public_key_name);
		write_file((unsigned char*)sk, CRYPTO_SECRETKEYBYTES, FOLDER, private_key_name);
		
	}
  
  return 0;
}

void write_file(const unsigned char* const restrict buffer, const size_t data_len, const char* const restrict folder, const char* const restrict name){
	FILE* tmp;
	char* path;
	if((path = malloc(sizeof(char)*sizeof(folder)*sizeof(name) + 1UL)) == NULL){
		fprintf(stderr, "Error in allocating memory for full-path name\n");
		exit(1);
	}
  strcpy(path, folder);
  strcat(path, "/");
  strcat(path, name);
	if((tmp = fopen(path, "w")) == NULL){
		fprintf(stderr, "Error in opening %s. Error: %s\n", path, strerror(errno));
		exit(1);
	}
	if(fwrite(buffer, data_len, 1UL, tmp) != 1UL){
		fprintf(stderr, "Error in writing %s. Error: %s\n", path, strerror(errno));
		fclose(tmp);
		exit(1);
	}
	if(chmod(path, 7777) != 0){
		fprintf(stderr, "Error in chmod. Error: %s\n", strerror(errno));
		exit(1);
	}
	fclose(tmp);
	free(path);
}
