#include <openssl/pem.h>

#define MAX_BUF 1<<18
#define UPDATES_LEN 260

void sign(unsigned char* clear_buf, unsigned long* clear_size, char* prvkey_file_name);
void verify(unsigned char* file_buf, unsigned long* file_size, char* pubkey_file_name);
