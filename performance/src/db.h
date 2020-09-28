#define MAX_USER_LEN 32
#define MAX_ENCRYPTED_DEC_KEY_NAME_LEN 32
#define MAX_FILE_NAME_LEN 32
#define MAX_ATTRIBUTE_SET_LEN 256
#define DATABASE "test.db"

#define KEY_VERSION 0
#define UPDATED_KEY_VERSION 1
#define CIPHERTEXT_VERSION 2
#define UPDATED_CIPHERTEXT_VERSION 3
#define MAX_MATCHES 20
#define VERSION_REGEX "_v_[0-9]{1,10}"
#define TMP_KEY

typedef struct{
	char* brand;
	uint32_t year;
	char* model;
	uint32_t ECU_1;
	uint32_t ECU_2;
	uint32_t ECU_3;
} attribute_s;

typedef struct {
	char encryped_decryption_key_name[MAX_ENCRYPTED_DEC_KEY_NAME_LEN];
	char encrypted_file_name[MAX_FILE_NAME_LEN];
	char current_attribute_set[MAX_ATTRIBUTE_SET_LEN];
	uint32_t key_version;
	uint32_t updated_key_version;
	uint32_t ciphertext_version;
	uint32_t updated_ciphertext_version;
} user_info;

void open_db(sqlite3** db);

void close_db(sqlite3* db);

void check_error(const int rc, sqlite3* db);

void get_user_info(sqlite3* db, const char* const restrict user, user_info* restrict* const restrict ui);

int update_attribute_set(sqlite3* db, const char* const restrict user, const char* const restrict new_attribute_set);

void initialize_db(sqlite3* db);

int update_version(sqlite3* db, const char* const restrict user, const int type, const uint32_t new_version);

void make_attribute_set(char* const restrict attributes, const attribute_s* const restrict attr_s, const uint32_t version);

void bswabe_keygen_bis(const char* const restrict attribute_set, char* restrict msk_file, bswabe_pub_t* const restrict pub, char* const restrict out_file);

void make_version_regex(const uint32_t arg, char* restrict* const restrict buffer);

char *str_replace(char* restrict orig, const char* const restrict rep, const char* restrict with);

void get_policy_or_attribute_version(char* const restrict source, const char* const restrict regex_string, uint32_t* const restrict res);
