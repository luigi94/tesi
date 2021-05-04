#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include "katrng.h"
#include "api.h"

#define PUBLIC_KEY_NAME_PREFIX "srvpubkey%u"
#define PRIVATE_KEY_NAME_PREFIX "srvprvkey%u"

#if FALCON_MODE == 2
#define FOLDER "FALCON512_keys"
#elif FALCON_MODE == 5
#define FOLDER "FALCON1024_keys"
#endif

#define KEY_NAME_LEN 16UL
#define NUM 500U


void write_file(const unsigned char* const restrict buffer, const size_t data_len, const char* const restrict folder, const char* const restrict name);
struct stat st = {0};

int main(void){

	char public_key_name[KEY_NAME_LEN];
	char private_key_name[KEY_NAME_LEN];	
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];

	fprintf(stdout, "Parameters:\nCRYPTO_SECRETKEYBYTES: %d\nCRYPTO_PUBLICKEYBYTES: %d\nCRYPTO_BYTES: %d\nCRYPTO_ALGNAME: %s\n\n", CRYPTO_SECRETKEYBYTES, CRYPTO_PUBLICKEYBYTES, CRYPTO_BYTES, CRYPTO_ALGNAME);
  
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
