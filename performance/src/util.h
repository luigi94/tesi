#include <openssl/pem.h>

#define BUFFERSIZE 32
#define SGNSIZE 128

void sign(unsigned char* clear_buf, unsigned char* sgnt_buf, unsigned clear_size, unsigned* sgnt_size, EVP_PKEY* prvkey);

void verify(unsigned char* file_buf, long file_size, unsigned char* sgn_buf, EVP_PKEY* pubkey);
