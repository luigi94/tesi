#include <openssl/evp.h>
#include <openssl/pem.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include "util.h"

void sign(const unsigned char* const restrict clear_buf, const unsigned long clear_size, unsigned char* restrict* const restrict sgnt_buf, unsigned long* const restrict sgnt_size, const char* const restrict prvkey_file_name){
	const EVP_MD* md;
	EVP_MD_CTX* md_ctx;
	int ret;
	FILE* prvkey_file;
	EVP_PKEY* prvkey;
	unsigned expected_sgn_size;
	unsigned tmp;
	
	if(clear_size > INT_MAX){
		fprintf(stderr, "Buffer to sign too big\n");
		exit(1);
	}
	
	if((prvkey_file = fopen(prvkey_file_name, "r")) == NULL){
		fprintf(stderr, "Error: cannot open file '%s' (missing?)\n", prvkey_file_name);
		exit(1);
	}
	prvkey = PEM_read_PrivateKey(prvkey_file, NULL, NULL, NULL);
	fclose(prvkey_file);
	expected_sgn_size = (unsigned) EVP_PKEY_size(prvkey);

	if((*sgnt_buf = (unsigned char*)malloc((size_t)expected_sgn_size)) == NULL){
		fprintf(stderr, "Error in allocating memory for signature. Error: %s\n", strerror(errno));
		exit(1);
	}
	// create the signature context:
	md = EVP_sha256();
	md_ctx = EVP_MD_CTX_new();
	if(!md_ctx){
		fprintf(stderr, "Error: EVP_MD_CTX_new returned NULL\n");
		exit(1);
	}

	if(EVP_SignInit(md_ctx, md) == 0){
		fprintf(stderr, "Error: EVP_SignInit returned %d\n", ret);
		exit(1);
	}
	if(EVP_SignUpdate(md_ctx, clear_buf, (unsigned)clear_size) == 0){
		fprintf(stderr, "Error: EVP_SignUpdate returned %d\n", ret);
		exit(1);
	}
	if(EVP_SignFinal(md_ctx, *sgnt_buf, &tmp, prvkey) == 0){
		fprintf(stderr, "Error: EVP_SignFinal returned %d\n", ret);
		exit(1);
	}
	if(tmp < expected_sgn_size){
		fprintf(stderr, "Error in signing, signature size does not match expected size\n");
		exit(1);
	}
	
	fprintf(stdout, "Signature size: %u, as expected\n", tmp);
	
	*sgnt_size = (unsigned long)tmp;
	
	// delete the digest and the private key from memory:
	EVP_MD_CTX_free(md_ctx);
	EVP_PKEY_free(prvkey);
}

void verify(const unsigned char* const restrict file_buf, unsigned long* const restrict file_size, const char* const restrict pubkey_file_name){
	// declare some useful variables:
	int ret;
	FILE* pubkey_file;
	EVP_PKEY* pubkey;
	unsigned char* sgnt_buf;
	unsigned sgnt_size;
	
	pubkey_file = fopen(pubkey_file_name, "r");
	if(!pubkey_file){
		fprintf(stderr, "Error: cannot open file '%s' (missing?)\n", pubkey_file_name);
		exit(1);
	}
	pubkey = PEM_read_PUBKEY(pubkey_file, NULL, NULL, NULL);
	sgnt_size = (unsigned) EVP_PKEY_size(pubkey);
	fprintf(stdout, "Signature size: %d\n", sgnt_size);
	fclose(pubkey_file);
	
	const EVP_MD* md = EVP_sha256();
	EVP_MD_CTX* md_ctx;
	
	*file_size -= (unsigned long)sgnt_size;
	if((sgnt_buf = (unsigned char*)malloc((size_t)sgnt_size)) == NULL){
		fprintf(stderr, "Error in allocating memory for signature. Error: %s\n", strerror(errno));
		exit(1);
	}
	memcpy((void*)sgnt_buf, (void*)(file_buf + *file_size), (size_t)sgnt_size);
	
	// create the signature context:
	md_ctx = EVP_MD_CTX_new();
	if(!md_ctx){
		fprintf(stderr, "Error: EVP_MD_CTX_new returned NULL\n");
		exit(1);
	}

	if(EVP_VerifyInit(md_ctx, md) == 0){
		fprintf(stderr, "Error in EVP_VerifyInit\n");
		exit(1);
	}
	if(EVP_VerifyUpdate(md_ctx, file_buf, *file_size) == 0){
		fprintf(stderr, "Error in EVP_VerifyUpdate\n");
		exit(1); 
	}
	ret = EVP_VerifyFinal(md_ctx, sgnt_buf, sgnt_size, pubkey);
	if(ret == 0){ // it is 0 if invalid signature, -1 if some other error, 1 if success.
		fprintf(stderr, "Error: EVP_VerifyFinal failed: invalid signature\n");
		exit(1);
	} else if(ret == -1){
		fprintf(stderr, "Some error occured during signature verification\n");
		exit(1);
	}else if (ret == 1){
		fprintf(stdout, "Signature verified\n");
	}else{
		fprintf(stderr, "I shouldn't be printed. EVP_VerifyFinal returned %d\n", ret);
		exit(1);
	}
	EVP_MD_CTX_free(md_ctx);
	EVP_PKEY_free(pubkey);
	free(sgnt_buf);
}

void write_file(unsigned char* buffer, size_t data_len, char* name){
	FILE* tmp;
	if((tmp = fopen(name, "w")) == NULL){
		fprintf(stderr, "Error in opening %s. Error: %s\n", name, strerror(errno));
		exit(1);
	}
	fprintf(stdout, "I'm writing %lu bytes on %s\n", data_len, name);
	fwrite(buffer, data_len, 1, tmp);
	fclose(tmp);
}

unsigned long get_milliseconds(){
	struct timeval now;
	if(gettimeofday(&now, NULL) != 0){
		fprintf(stderr, "Error in gettimeofday(). Error: %s\n", strerror(errno));
		exit(1);
	}
	return (unsigned long) (now.tv_sec * 1000 + now.tv_usec / 1000);
}
