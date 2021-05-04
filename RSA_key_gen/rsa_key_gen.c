#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define PUBLIC_KEY_NAME_PREFIX "pub_key_%u_v%u"
#define PRIVATE_KEY_NAME_PREFIX "prv_key_%u_v%u"
#define KEY_NAME_LEN 17UL

int generate_key(const int bits, char* public_key_name, char* private_key_name){
	int	ret = 0;
	RSA *r = NULL;
	BIGNUM *bne = NULL;
	FILE *bp_public = NULL;
	FILE* bp_private = NULL;
	
	unsigned long	e = RSA_F4;

	// 1. generate rsa key
	bne = BN_secure_new();
	ret = BN_set_word(bne,e);
	if(ret != 1){
		goto free_all;
	}

	r = RSA_new();
	ret = RSA_generate_key_ex(r, bits, bne, NULL);
	if(ret != 1){
		goto free_all;
	}

	// 2. save public key
	bp_public = fopen(public_key_name, "w+");
	ret = PEM_write_RSAPublicKey(bp_public, r);
	fclose(bp_public);
	if(ret != 1){
		goto free_all;
	}

	// 3. save private key
	bp_private = fopen(private_key_name, "w+");
	ret = PEM_write_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);
	fclose(bp_private);

	// 4. free
	free_all:
	RSA_free(r);
	BN_clear_free(bne);

	return ret;
}

int main(int argc, char* argv[]) {
	int bits;
	char public_key_name[KEY_NAME_LEN];
	char private_key_name[KEY_NAME_LEN];
	
	if(argc != 2){
		fprintf(stderr, "Enter the number of bits\n");
		return 1;
	}
	bits = atoi(argv[1]);
	if(bits <= 0){
		fprintf(stderr, "Bad input paramters\n");
		return 1;
	}
	
	for (unsigned i = 0u; i < 1UL; i++) {
		snprintf(public_key_name, KEY_NAME_LEN, PUBLIC_KEY_NAME_PREFIX, (unsigned)bits, i);
		snprintf(private_key_name, KEY_NAME_LEN, PRIVATE_KEY_NAME_PREFIX, (unsigned)bits, i);
		
		if(generate_key(bits, "srvpubkey.pem", "srvprvkey.pem") != 1){
			fprintf(stderr, "Error in generating key\n");
			exit(1);
		}
	}
	return 0;
}
