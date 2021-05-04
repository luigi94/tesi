#include <openssl/evp.h>
#include <openssl/pem.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include "util.h"

unsigned expected_key_size(const char* const restrict prvkey_file_name){
	FILE* prvkey_file;
	EVP_PKEY* prvkey;
	unsigned exp_key_size;
	if((prvkey_file = fopen(prvkey_file_name, "r")) == NULL){
		fprintf(stderr, "Error: cannot open file '%s' (missing?)\n", prvkey_file_name);
		exit(1);
	}
	prvkey = PEM_read_PrivateKey(prvkey_file, NULL, NULL, NULL);
	fclose(prvkey_file);
	exp_key_size = EVP_PKEY_size(prvkey);
	EVP_PKEY_free(prvkey);
	return exp_key_size;
}

void sign(const unsigned char* const restrict clear_buf, const unsigned long clear_size, unsigned char* restrict* const restrict sgnt_buf, const unsigned long sgnt_size, const char* const restrict prvkey_file_name){
	const EVP_MD* md;
	EVP_MD_CTX* md_ctx;
	int ret;
	FILE* prvkey_file;
	EVP_PKEY* prvkey;
	unsigned actual_size;
	uint8_t remaining;
	
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

	if((*sgnt_buf = (unsigned char*)OPENSSL_malloc((size_t)sgnt_size)) == NULL){
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
	if(EVP_SignFinal(md_ctx, *sgnt_buf, &actual_size, prvkey) == 0){
		fprintf(stderr, "Error: EVP_SignFinal returned %d\n", ret);
		exit(1);
	}
	
	if(actual_size > sgnt_size - 1U){
		fprintf(stderr, "Error in signature size\n");
		exit(1);
	}
	remaining = (uint8_t) (sgnt_size - actual_size);
	memcpy((void*)(*sgnt_buf + sgnt_size - 1UL), (void*)&remaining, (size_t)1UL);
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
	uint8_t padding_bytes;
	
	pubkey_file = fopen(pubkey_file_name, "r");
	if(!pubkey_file){
		fprintf(stderr, "Error: cannot open file '%s' (missing?)\n", pubkey_file_name);
		exit(1);
	}
	pubkey = PEM_read_PUBKEY(pubkey_file, NULL, NULL, NULL);
	sgnt_size = (unsigned) EVP_PKEY_size(pubkey) + 1U;
	fclose(pubkey_file);
	
	const EVP_MD* md = EVP_sha256();
	EVP_MD_CTX* md_ctx;
	
	memcpy((void*)&padding_bytes, (void*)(file_buf + *file_size - 1U), 1UL);
	
	*file_size -= (unsigned long)sgnt_size;
	sgnt_size -= (unsigned) padding_bytes;
	
	if((sgnt_buf = (unsigned char*)OPENSSL_malloc((size_t)sgnt_size)) == NULL){
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
		// fprintf(stdout, "Signature verified\n");
	}else{
		fprintf(stderr, "I shouldn't be printed. EVP_VerifyFinal returned %d\n", ret);
		exit(1);
	}
	EVP_MD_CTX_free(md_ctx);
	EVP_PKEY_free(pubkey);
	OPENSSL_free(sgnt_buf);
}

void seal(const char* const restrict pubkey_file_name, const char* const restrict clear_file_name){
	int ret;
	
	FILE* pubkey_file;
	FILE* cphr_file;
	EVP_PKEY* pubkey;
	
	unsigned char* cphr_buf;
	unsigned long enc_buffer_size;
	
	FILE* clear_file;
	long int clear_size;
	unsigned char* clear_buf;

	int encrypted_key_len;
	int iv_len;
	int block_size;
	EVP_CIPHER_CTX* ctx;
	const EVP_CIPHER* cipher;
	
	unsigned char* encrypted_key;
	unsigned char* iv;
	
	int nc; // bytes encrypted at each chunk
	int nctot; // total encrypted bytes
	int cphr_size;

	// load the peer's public key:
	if((pubkey_file = fopen(pubkey_file_name, "rb")) == NULL){
		fprintf(stderr, "Error: cannot open file '%s' (missing?)\n", pubkey_file_name);
		exit(1);
	}
	pubkey = PEM_read_PUBKEY(pubkey_file, NULL, NULL, NULL);
	fclose(pubkey_file);
	if(!pubkey){
		fprintf(stderr, "Error: PEM_read_PUBKEY returned NULL\n");
		exit(1);
	}

	// open the file to encrypt:
	if((clear_file = fopen(clear_file_name, "rb")) == NULL) {
		fprintf(stderr, "Error: cannot open file '%s' (file does not exist?)\n", clear_file_name);
		exit(1);
	}

	// get the file size: 
	// (assuming no failures in fseek() and ftell())
	fseek(clear_file, 0, SEEK_END);
	clear_size = ftell(clear_file);
	rewind(clear_file);
	// read the plaintext from file:
	if((clear_buf = (unsigned char*)OPENSSL_malloc((size_t)clear_size)) == NULL){
		fprintf(stderr, "Error in allocating memory for clear buffer. Error: %s\n", strerror(errno));
		exit(1);
	}
	if(fread(clear_buf, 1, (size_t) clear_size, clear_file) < (size_t)clear_size){
		fprintf(stderr, "Error while reading file '%s'\n", clear_file_name);
		exit(1);
	}
	fclose(clear_file);
	cipher = EVP_aes_256_cbc();
	encrypted_key_len = EVP_PKEY_size(pubkey);
	iv_len = EVP_CIPHER_iv_length(cipher);
	block_size = EVP_CIPHER_block_size(cipher);
	// create the envelope context
	if((ctx = EVP_CIPHER_CTX_new()) == NULL){
		fprintf(stderr, "Error: EVP_CIPHER_CTX_new returned NULL\n");
		exit(1);
	}

	// allocate buffers for encrypted key and IV:
	if((encrypted_key = (unsigned char*)OPENSSL_malloc((size_t)encrypted_key_len)) == NULL){
		fprintf(stderr, "Error in allocating memory for encrypted key. Error: %s\n", strerror(errno));
		exit(1);
	}
	
	if((iv = (unsigned char*)OPENSSL_malloc((size_t)iv_len)) == NULL){
		fprintf(stderr, "Error in allocating memory for initialization vector. Error: %s\n", strerror(errno));
		exit(1);
	}
	
	if(clear_size > INT_MAX - block_size){
		fprintf(stderr, "Error: integer overflow (file too big?)\n");
		exit(1);
	}

	// allocate a buffer for the ciphertext:
	enc_buffer_size = (size_t)(clear_size + block_size);
	if((cphr_buf = (unsigned char*)OPENSSL_malloc(enc_buffer_size)) == NULL){
		fprintf(stderr, "Error in allocating memory for encrypted buffer. Error: %s\n", strerror(errno));
		exit(1);
	}

	// encrypt the plaintext:
	// (perform a single update on the whole plaintext, 
	// assuming that the plaintext is not huge)
	ret = EVP_SealInit(ctx, cipher, &encrypted_key, &encrypted_key_len, iv, &pubkey, 1);
	if(ret <= 0){ // it is "<=0" to catch the (undocumented) case of -1 return value, when the operation is not supported (e.g. attempt to use digital envelope with Elliptic Curve keys)
		fprintf(stderr, "Error: EVP_SealInit returned %d\n", ret);
		exit(1);
	}
	nc = 0; // bytes encrypted at each chunk
	nctot = 0; // total encrypted bytes
	ret = EVP_SealUpdate(ctx, cphr_buf, &nc, clear_buf, clear_size);  
	if(ret == 0){
		fprintf(stderr, "Error: EVP_SealUpdate returned %d\n", ret);
		exit(1);
	}
	nctot += nc;
	ret = EVP_SealFinal(ctx, cphr_buf + nctot, &nc);
	if(ret == 0){
		fprintf(stderr, "Error: EVP_SealFinal returned %d\n", ret);
		exit(1);
	}
	nctot += nc;
	cphr_size = nctot;

	// delete the symmetric key and the plaintext from memory:
	EVP_CIPHER_CTX_free(ctx);
	memset(clear_buf, 0, clear_size);
	OPENSSL_free(clear_buf);
	
	if((cphr_file = fopen(clear_file_name, "wb")) == NULL){
		fprintf(stderr, "Error: cannot open file '%s' (no permissions?)\n", clear_file_name);
		exit(1);
	}
	if(fwrite((void*)encrypted_key, 1UL, (size_t) encrypted_key_len, cphr_file) < (size_t) encrypted_key_len) {
		fprintf(stderr, "Error while writing encryption key onto the file '%s'\n", clear_file_name);
		exit(1);
	}
	memset((void*)encrypted_key, 0, (size_t) encrypted_key_len);
	OPENSSL_free(encrypted_key);
	if(fwrite((void*)iv, 1UL, (size_t) iv_len, cphr_file) < (size_t) iv_len){
		fprintf(stderr, "Error while writing initializtion vector onto the file '%s'\n", clear_file_name);
		exit(1);
	}
	memset((void*)iv, 0, (size_t) iv_len);
	OPENSSL_free(iv);
	if(fwrite((void*)cphr_buf, 1UL, (size_t) cphr_size, cphr_file) < (size_t)cphr_size) {
		fprintf(stderr, "Error while writing ciphertext onto the file '%s'\n", clear_file_name);
		exit(1);
	}
	memset((void*)cphr_buf, 0, (size_t) cphr_size);
	OPENSSL_free(cphr_buf);
	fclose(cphr_file);
	
	EVP_PKEY_free(pubkey);
}

void unseal(const char* const restrict prvkey_file_name, const unsigned char* const restrict ek_iv_cphr_buf, const unsigned long ek_iv_cphr_size, unsigned char* restrict* const restrict clear_buf, unsigned long* const restrict clear_size){
	int ret; // used for return values
	FILE* prvkey_file;
	EVP_PKEY* prvkey;
	
	const EVP_CIPHER* cipher;
	
	unsigned char* encrypted_key;
	unsigned char* iv;
	unsigned char* cphr_buf;
	int encrypted_key_len;
	int iv_len;
	int cphr_size;
	
	EVP_CIPHER_CTX* ctx;
	
	int nd; // bytes decrypted at each chunk
	int ndtot;

	// load my private key:
	if((prvkey_file = fopen(prvkey_file_name, "r")) == NULL){
		fprintf(stderr, "Error: cannot open file '%s' (missing?)\n", prvkey_file_name);
		exit(1);
	}
	
	prvkey = PEM_read_PrivateKey(prvkey_file, NULL, NULL, NULL);
	fclose(prvkey_file);
	
	if(!prvkey){
		fprintf(stderr, "Error: PEM_read_PrivateKey returned NULL\n");
		exit(1);
	}
	
	// declare some useful variables:
	cipher = EVP_aes_256_cbc();
	encrypted_key_len = EVP_PKEY_size(prvkey);
	iv_len = EVP_CIPHER_iv_length(cipher);

	// check for possible integer overflow in (encrypted_key_len + iv_len)
	// (theoretically possible if the encrypted key is too big):
	if(encrypted_key_len > INT_MAX - iv_len){
		fprintf(stderr, "Error: integer overflow (encrypted key too big?)\n");
		exit(1);
	}
	// check for correct format of the encrypted file
	// (size must be >= encrypted key size + IV + 1 block):
	if(ek_iv_cphr_size < (unsigned long)(encrypted_key_len + iv_len)) {
		fprintf(stderr, "Error: encrypted file with wrong format\n");
		exit(1);
	}

	// allocate buffers for encrypted key, IV, ciphertext, and plaintext:
	if((encrypted_key = (unsigned char*)OPENSSL_malloc((size_t)encrypted_key_len)) == NULL){
		fprintf(stderr, "Error in allocating memory for the encrypted key. Error: %s\n", strerror(errno));
		exit(1);
	}
	if((iv = (unsigned char*)OPENSSL_malloc((size_t)iv_len)) == NULL){
		fprintf(stderr, "Error in allocating memory for the initalization vector. Error: %s\n", strerror(errno));
		exit(1);
	}
	
	if((cphr_buf = (unsigned char*)OPENSSL_malloc((size_t)ek_iv_cphr_size)) == NULL){
		fprintf(stderr, "Error in allocating memory for ciphertext. Error: %s\n", strerror(errno));
		exit(1);
	}
	
	cphr_size = ek_iv_cphr_size - encrypted_key_len - iv_len;
	if((*clear_buf = (unsigned char*)OPENSSL_malloc((size_t)cphr_size)) == NULL){
		fprintf(stderr, "Error in allocating memory for the cleartext buffer. Error: %s\n", strerror(errno));
		exit(1);
	}

	// read the encrypted key, the IV, and the ciphertext from file:
	memcpy((void*)encrypted_key, (void*)ek_iv_cphr_buf, (size_t)encrypted_key_len);
	memcpy((void*)iv, (void*)(ek_iv_cphr_buf + (unsigned long)encrypted_key_len), (size_t)iv_len);
	memcpy((void*)cphr_buf, (void*)(ek_iv_cphr_buf + (unsigned long)encrypted_key_len + (unsigned long)iv_len), (size_t)cphr_size);

	// create the envelope context:
	if((ctx = EVP_CIPHER_CTX_new()) == NULL){
		fprintf(stderr, "Error: EVP_CIPHER_CTX_new returned NULL\n");
		exit(1);
	}
	// decrypt the ciphertext:
	// (perform a single update on the whole ciphertext, 
	// assuming that the ciphertext is not huge)
	ret = EVP_OpenInit(ctx, cipher, encrypted_key, encrypted_key_len, iv, prvkey);
	if(ret == 0){
		fprintf(stderr, "Error: EVP_OpenInit returned %d\n", ret);;
		exit(1);
	}
	nd = 0; 
	ndtot = 0;
	ret = EVP_OpenUpdate(ctx, *clear_buf, &nd, cphr_buf, cphr_size);
	if(ret == 0){
		fprintf(stderr, "Error: EVP_OpenUpdate returned %d\n", ret);
		exit(1);
	}
	ndtot += nd;
	ret = EVP_OpenFinal(ctx, *clear_buf + ndtot, &nd);
	if(ret == 0){
		fprintf(stderr, "Error: EVP_OpenFinal returned %d (corrupted file?)\n", ret);
		exit(1);
	}
	ndtot += nd;
	*clear_size = (unsigned long)ndtot;
	if((*clear_buf = (unsigned char*)realloc(*clear_buf, *clear_size)) == NULL){
		fprintf(stderr, "Error in reallocating memory for cleartext. Error: %s\n", strerror(errno));
		exit(1);
	}

	// delete the symmetric key and the private key from memory:
	EVP_CIPHER_CTX_free(ctx);
	EVP_PKEY_free(prvkey);
	
	// deallocate buffers:
	OPENSSL_free(encrypted_key);
	OPENSSL_free(iv);
	OPENSSL_free(cphr_buf);
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

unsigned long get_milliseconds(){
	struct timeval now;
	if(gettimeofday(&now, NULL) != 0){
		fprintf(stderr, "Error in gettimeofday(). Error: %s\n", strerror(errno));
		exit(1);
	}
	return (unsigned long) (now.tv_sec * 1000 + now.tv_usec / 1000);
}
