#include <stdio.h> // for fopen(), etc.
#include <string.h>
#include <openssl/evp.h>

#include "util.h"

void sign(unsigned char* clear_buf, unsigned char* sgnt_buf, unsigned clear_size, unsigned* sgnt_size, EVP_PKEY* prvkey){
	const EVP_MD* md;
	EVP_MD_CTX* md_ctx;
	int ret;
	
	// create the signature context:
	md = EVP_sha256();
	md_ctx = EVP_MD_CTX_new();
	if(!md_ctx){
		fprintf(stderr, "Error: EVP_MD_CTX_new returned NULL\n");
		exit(1);
	}

	// sign the plaintext:
	// (perform a single update on the whole plaintext, 
	// assuming that the plaintext is not huge)
	ret = EVP_SignInit(md_ctx, md);
	if(ret == 0){
		fprintf(stderr, "Error: EVP_SignInit returned %d\n", ret);
		exit(1);
	}
	ret = EVP_SignUpdate(md_ctx, clear_buf, clear_size);
	if(ret == 0){
		fprintf(stderr, "Error: EVP_SignUpdate returned %d\n", ret);
		exit(1);
	}
	
	ret = EVP_SignFinal(md_ctx, sgnt_buf, &(*sgnt_size), prvkey);
	if(ret == 0){
		fprintf(stderr, "Error: EVP_SignFinal returned %d\n", ret);
		exit(1);
	}
	// delete the digest and the private key from memory:
	EVP_MD_CTX_free(md_ctx);
	EVP_PKEY_free(prvkey);

}

void verify(unsigned char* file_buf, long file_size, unsigned char* sgn_buf, EVP_PKEY* pubkey){
	// declare some useful variables:
	const EVP_MD* md = EVP_sha256();
	EVP_MD_CTX* md_ctx;
	int ret;

	// create the signature context:
	md_ctx = EVP_MD_CTX_new();
	
	if(!md_ctx){
		fprintf(stderr, "Error: EVP_MD_CTX_new returned NULL\n");
		exit(1);
	}

	// verify the plaintext:
	// (perform a single update on the whole plaintext, 
	// assuming that the plaintext is not huge)
	ret = EVP_VerifyInit(md_ctx, md);
	if(ret == 0){
		fprintf(stderr, "Error: EVP_VerifyInit returned %d\n", ret);
		exit(1);
	}
	ret = EVP_VerifyUpdate(md_ctx, file_buf, file_size);  
	if(ret == 0){
		fprintf(stderr, "Error: EVP_VerifyUpdate returned %d\n", ret);
		exit(1); 
	}
	ret = EVP_VerifyFinal(md_ctx, sgn_buf, SGNSIZE, pubkey);
	if(ret != 1){ // it is 0 if invalid signature, -1 if some other error, 1 if success.
		fprintf(stderr, "Error: EVP_VerifyFinal returned %d (invalid signature?)\n", ret);
		exit(1);
	}

	EVP_MD_CTX_free(md_ctx);
	EVP_PKEY_free(pubkey);

}
