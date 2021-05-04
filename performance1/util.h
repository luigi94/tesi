#define SERVER_NAME_LEN_MAX 255
#define MAX_USER_LENGTH 64

#define MAX_BUF 1<<18
#define UPDATES_LEN 260
#define TIMESTAMP_LEN 8
#define TYPE_LEN 1
#define LENGTH_FIELD_LEN 8
#define EXP_SGNT_SIZE 512
#define FRESHNESS_THRESHOLD 60

void sign(const unsigned char* const restrict clear_buf, const unsigned long clear_size, unsigned char* restrict* const restrict sgnt_buf, unsigned long* const restrict sgnt_size, const char* const restrict prvkey_file_name);
void verify(const unsigned char* const restrict file_buf, unsigned long* const restrict file_size, const char* const restrict pubkey_file_name);

void seal(const char* const restrict pubkey_file_name, const char* const restrict clear_file_name);
void unseal(const char* const restrict prvkey_file_name, const unsigned char* const restrict ek_iv_cphr_buf, const unsigned long ek_iv_cphr_size, unsigned char* restrict* const restrict clear_buf, unsigned long* const restrict clear_size);
unsigned expected_key_size(const char* const restrict prvkey_file_name);

void write_file(const unsigned char* const restrict buffer, const size_t data_len, const char* const restrict name);

unsigned long get_milliseconds();
