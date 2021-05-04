void close_socket(const int socket_fd);

int fetch_public_key(uint8_t* pk, char* public_key_name);
int fetch_private_key(uint8_t* sk, char* private_key_name);

void write_file(const unsigned char* const restrict buffer, const size_t data_len, const char* const restrict name);
unsigned long get_milliseconds();
