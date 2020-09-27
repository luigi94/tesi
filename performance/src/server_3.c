#include <sqlite3.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>

#include <sys/stat.h>
#include <errno.h>

#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>

#include <netinet/tcp.h>

#include "bswabe.h"
#include "common.h"
#include "private.h"
#include "util.h"
#include "db.h"
#include "policy_lang.h"

#define BACKLOG 10

ssize_t nbytes;
size_t ret;
int socket_fd;

sqlite3* db = NULL;

char* msk_file = "master_key";
char* pub_file = "pub_key";
char* srvprvkey = "srvprvkey.pem";

typedef struct pthread_arg_t {
    int new_socket_fd;
    struct sockaddr_in client_address;
    pthread_mutex_t* mutex;
} pthread_arg_t;

/* Thread routine to serve connection to client. */
void *pthread_routine(void *arg);
void *key_authority_routine(void *arg);

/* Signal handler to handle SIGTERM and SIGINT signals. */
void signal_handler();

void receive_username_size(const int new_socket_fd, size_t* const restrict username_size){
	nbytes = recv(new_socket_fd, (void*)username_size, (size_t) sizeof(size_t), 0);
	if(nbytes < 0){
		fprintf(stderr, "Error in receiving unsername size from socket %d. Error: %s\n", new_socket_fd, strerror(errno));
		close(new_socket_fd);
		exit(1);
	}
	if((unsigned long) nbytes < sizeof(size_t)){
		fprintf(stderr, "Username size not entirely received on socket %d. Error: %s\n", new_socket_fd, strerror(errno));
		close(new_socket_fd);
		exit(1);
	}
}
void receive_username(const int new_socket_fd, char* const restrict user, const size_t username_size){
	nbytes = recv(new_socket_fd, (void*)user, (size_t) username_size, 0);
	if(nbytes < 0){
		fprintf(stderr, "Error in receiving username from socket %d. Error: %s\n", new_socket_fd, strerror(errno));
		close(new_socket_fd);
		exit(1);
	}
	if((size_t) nbytes < username_size){
		fprintf(stderr, "Username not entirely received on socket %d. Error: %s\n", new_socket_fd, strerror(errno));
		close(new_socket_fd);
		exit(1);
	}
}

void send_data(const int new_socket_fd, const unsigned char* const restrict to_send, const unsigned long total_len){

  unsigned long offset;
  unsigned long remaining_data;
  
	nbytes = send(new_socket_fd, (void*)to_send, (size_t)LENGTH_FIELD_LEN, 0);
	if(nbytes < 0){
		fprintf(stderr, "Error in sending firmware updates size on socket %d. Error: %s\n", new_socket_fd, strerror(errno));
		close(new_socket_fd);
		exit(1);
	}
	if((size_t) nbytes < LENGTH_FIELD_LEN){
		fprintf(stdout, "WARNING - Firmware updates size not entirely sent on socket %d\n", new_socket_fd);
		close(new_socket_fd);
		exit(1);
	}
	
	offset = LENGTH_FIELD_LEN;
	remaining_data = total_len - LENGTH_FIELD_LEN;
	while (remaining_data > 0) {
		size_t count = (size_t) (MAX_BUF < remaining_data ? MAX_BUF : remaining_data);
		nbytes = send(new_socket_fd, (void*)(to_send + offset), count, 0);
		fprintf(stdout, "Sent %ld bytes on expected %lu\n", nbytes, count);
		if(nbytes < 0){
			fprintf(stderr, "Error in sending firmware updates chunk on socket %d. Error: %s\n", new_socket_fd, strerror(errno));
			close(new_socket_fd);
			exit(1);
		}
		if((size_t) nbytes < count){
			fprintf(stdout, "WARNING - Firmware updates chunk not entirely sent on socket %d\n", new_socket_fd);
			//close(new_socket_fd);
			//exit(1);
		}
		remaining_data -= nbytes;
		offset += (unsigned long)nbytes;
	}
}

void make_buffer_and_sign(const char* const restrict ciphertext_file, const char* const restrict enc_key_file, unsigned char* restrict* const restrict buffer, unsigned long* const total_len, char* const restrict prvkey_file_name){
  FILE* f_ciphertext;
  FILE* f_key;
  
  unsigned long ciphertext_len;
	unsigned long time_stamp;
	unsigned char* sgnt_buf;
	unsigned long sgnt_size;
	unsigned long key_len;
	
	unsigned long pointer;
	
	/*
	.-----------------------------------------------------------------------------.
	| TOTAL LEN | TIMESTAMP |  KEY LEN  | DECRYPTION KEY | CIPHERTEXT | SIGNATURE |
	|  8 BYTES  |  8 BYTES  |  8 BYTES  |    VARIABLE    |  VARIABLE  | 512 BYTES |
	|           |           |           |      SIZE      |		SIZE    |           |
	'-----------------------------------------------------------------------------'
	*/
	
	/* Allocating memory for total len (it will be updated at the end of this function) */
	if((*buffer = (unsigned char*)malloc((size_t)LENGTH_FIELD_LEN)) == NULL){
		fprintf(stderr, "Error in allocating memory for message total length. Error: %s\n", strerror(errno));
		exit(1);
	}
	*total_len = LENGTH_FIELD_LEN;
	
	/* Adding timestamp */
	time_stamp = (unsigned long)time(NULL);
	pointer = *total_len;
	*total_len += (unsigned long)TIMESTAMP_LEN;
	if((*buffer = (unsigned char*)realloc(*buffer, *total_len)) == NULL){
		fprintf(stderr, "Error in reallocating memory for timestamp. Error: %s\n", strerror(errno));
		exit(1);
	}
	fprintf(stdout, "Appended timestamp %lu\n", time_stamp);
	memcpy((void*)(*buffer + pointer), (void*)&time_stamp, (size_t)TIMESTAMP_LEN);
	
	/* Adding key and key len if needed but first allocating memory for key len
	since this is needed in both cases */
	pointer = *total_len;
	*total_len += (unsigned long)LENGTH_FIELD_LEN;
	if((*buffer = (unsigned char*)realloc(*buffer, *total_len)) == NULL){
		fprintf(stderr, "Error in reallocating memeory for key length. Error: %s\n", strerror(errno));
		exit(1);
	}
	if(enc_key_file != NULL){
		if((f_key = fopen(enc_key_file, "r")) == NULL){
			fprintf(stderr, "Error in opening %s. Error: %s\n", enc_key_file, strerror(errno));
			exit(1);
		}
		fseek(f_key, 0UL, SEEK_END);
		key_len = (unsigned long)ftell(f_key);
		rewind(f_key);
		
		/* Adding key len */
		memcpy((void*)(*buffer + pointer), (void*)&key_len, (size_t)LENGTH_FIELD_LEN);
	
		pointer = *total_len;
		*total_len += key_len;
		if((*buffer = (unsigned char*)realloc(*buffer, *total_len)) == NULL){
			fprintf(stderr, "Error in realloc(). Error: %s\n", strerror(errno));
			exit(1);
		}
		if(fread((void*)(*buffer + pointer), 1, key_len, f_key) < key_len){
			fprintf(stderr, "Error while reading file '%s'. Error: %s\n", enc_key_file, strerror(errno));
			exit(1);
		}
		fclose(f_key);
	} else{
		key_len = 0UL;
		memcpy((void*)(*buffer + pointer), (void*)&key_len, (size_t)LENGTH_FIELD_LEN);
	}
  
  /* Adding ciphertext */
	if((f_ciphertext = fopen(ciphertext_file, "r")) == NULL){
		fprintf(stderr, "Error in opening %s. Error: %s\n", ciphertext_file, strerror(errno));
		exit(1);
	}
	
	fseek(f_ciphertext, 0, SEEK_END);
	ciphertext_len = ftell(f_ciphertext);
	rewind(f_ciphertext);
	
	pointer = *total_len;
	*total_len += ciphertext_len;
	if((*buffer = (unsigned char*)realloc(*buffer, *total_len)) == NULL){
		fprintf(stderr, "Error in reallocating memory for ciphertext. Error: %s\n", strerror(errno));
		exit(1);
	}
	if(fread((void*)(*buffer + pointer), 1, ciphertext_len, f_ciphertext) < ciphertext_len){
		fprintf(stderr, "Error while reading file '%s'. Error: %s\n", ciphertext_file, strerror(errno));
		exit(1);
	}
	fclose(f_ciphertext);
	
	pointer = *total_len;
	*total_len += (unsigned long) EXP_SGNT_SIZE;
	memcpy((void*)*buffer, (void*)&(*total_len), LENGTH_FIELD_LEN);
	
	sign(*buffer, *total_len - (unsigned long) EXP_SGNT_SIZE, &sgnt_buf, &sgnt_size, prvkey_file_name);
	
	if(sgnt_size != (unsigned long) EXP_SGNT_SIZE){
		fprintf(stderr, "Signature size does not match expected size\n");
		exit(1);
	}
	
	/* Adding signature */
	if((*buffer = (unsigned char*)realloc(*buffer, *total_len)) == NULL){
		fprintf(stderr, "Error in reallocating memeory for signature. Error: %s\n", strerror(errno));
		exit(1);
	}
	memcpy((void*)(*buffer + pointer), (void*)sgnt_buf, sgnt_size);
	
	free(sgnt_buf);
	
	fprintf(stdout, "Total length to send: %lu\n", *total_len);
}

void initialize_key_authority_thread(pthread_mutex_t* mutex){
	pthread_attr_t pthread_attr;
	pthread_t pthread;
	if (pthread_attr_init(&pthread_attr) != 0) {
		perror("pthread_attr_init");
		exit(1);
	}
	if (pthread_attr_setdetachstate(&pthread_attr, PTHREAD_CREATE_DETACHED) != 0) {
		perror("pthread_attr_setdetachstate");
		exit(1);
	}
	if (pthread_create(&pthread, &pthread_attr, key_authority_routine, (void*)mutex) != 0) {
		perror("pthread_create");
		exit(1);
	}
}

int main(int argc, char *argv[]) {
	int port, new_socket_fd;
	struct sockaddr_in address;
	pthread_attr_t pthread_attr;
	pthread_arg_t *pthread_arg;
	pthread_t pthread;
	socklen_t client_address_len;
	pthread_mutex_t mutex;

	if(argc != 2){
		fprintf(stderr, "Usage: ./server PORT\n");
		exit(1);
	}
	port = atoi(argv[1]);
	
	/* Initialize database */
	initialize_db(db);
	
	if(pthread_mutex_init(&mutex, NULL) != 0){
		fprintf(stderr, "Error in mutex initialization\n");
		exit(1);
	}
	initialize_key_authority_thread(&mutex);
	
	/* Initialise IPv4 address. */
	memset(&address, 0, sizeof address);
	address.sin_family = AF_INET;
	address.sin_port = htons(port);
	address.sin_addr.s_addr = INADDR_ANY;

	/* Create TCP socket. */
	if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		exit(1);
	}

	/* Bind address to socket. */
	if (bind(socket_fd, (struct sockaddr *)&address, sizeof address) == -1) {
		perror("bind");
		exit(1);
	}

	/* Listen on socket. */
	if (listen(socket_fd, BACKLOG) == -1) {
		perror("listen");
		exit(1);
	}

	/* Assign signal handlers to signals. */
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		perror("signal");
		exit(1);
	}
	if (signal(SIGTERM, signal_handler) == SIG_ERR) {
		perror("signal");
		exit(1);
	}
	
	if (signal(SIGINT, signal_handler) == SIG_ERR) {
		perror("signal");
		exit(1);
	}

	/* Initialise pthread attribute to create detached threads. */
	if (pthread_attr_init(&pthread_attr) != 0) {
		perror("pthread_attr_init");
		exit(1);
	}
	if (pthread_attr_setdetachstate(&pthread_attr, PTHREAD_CREATE_DETACHED) != 0) {
		perror("pthread_attr_setdetachstate");
		exit(1);
	}

	while (1) {
		/* Create pthread argument for each connection to client. */
		pthread_arg = (pthread_arg_t *)malloc(sizeof *pthread_arg);
		if (!pthread_arg) {
			perror("malloc");
			continue;
		}

		/* Accept connection to client. */
		client_address_len = sizeof pthread_arg->client_address;
		new_socket_fd = accept(socket_fd, (struct sockaddr *)&pthread_arg->client_address, &client_address_len);
		if (new_socket_fd == -1) {
			perror("accept");
			free(pthread_arg);
			continue;
		}
		fprintf(stdout, "New socket: %d\n", new_socket_fd);

		/* Initialise pthread argument. */
		pthread_arg->new_socket_fd = new_socket_fd;
		pthread_arg->mutex = &mutex;

		/* Create thread to serve connection to client. */
		if (pthread_create(&pthread, &pthread_attr, pthread_routine, (void *)pthread_arg) != 0) {
			perror("pthread_create");
			free(pthread_arg);
			continue;
		}
	}
	return 0;
}

void *pthread_routine(void *arg) {
	pthread_arg_t *pthread_arg = (pthread_arg_t *)arg;
  int new_socket_fd = pthread_arg->new_socket_fd;
  //struct sockaddr_in client_address = pthread_arg->client_address;
  pthread_mutex_t* mutex = pthread_arg->mutex;
  free(arg);
	char* user;
	size_t username_size;
  unsigned char* buffer;
  unsigned long total_len;
  
  user_info* ui = NULL;
  receive_username_size(new_socket_fd, &username_size);
	if((user = (char*)malloc(username_size)) == NULL){
		fprintf(stderr, "Error in allocating memory for username. Error: %s\n", strerror(errno));
		close(new_socket_fd);
		exit(1);
	}
	
	receive_username(new_socket_fd, user, username_size);
	
	pthread_mutex_lock(mutex);
	
	open_db(&db);
	
	get_user_info(db, user, &ui);
	
	if(ui == NULL){
		fprintf(stderr, "User %s not found\n", user);
		close_db(db);
		return NULL;
	}
	
	fprintf(stdout, "Encrypted decryption key name: %s, Encrypted file name: %s ", ui->encryped_decryption_key_name, ui->encrypted_file_name);
	fprintf(stdout, " Key version: %u, Updated key version: %u, Ciphertext version: %u, Updateted ciphertext version: %u\n", ui->key_version, ui->updated_key_version, ui->ciphertext_version, ui->updated_ciphertext_version);
	
	if(ui->key_version < ui->updated_key_version){
		fprintf(stdout, "User %s has version %u, updated version is %u, hence proceeding to send the new key and the new ciphertext\n", user, ui->key_version, ui->updated_key_version);
		make_buffer_and_sign(ui->encrypted_file_name, ui->encryped_decryption_key_name, &buffer, &total_len, srvprvkey);
		if(!update_version(db, user, KEY_VERSION, ui->updated_key_version)){
			fprintf(stderr, "Could not udate database upon receiving a request from a old-versioned client\n");
			pthread_mutex_unlock(mutex);
			exit(1);
		}
	
	}else if(ui->key_version == ui->updated_key_version){
		fprintf(stdout, "User %s has version %u, updated version is %u, hence there is no need to send the new key\n", user, ui->key_version, ui->updated_key_version);
		make_buffer_and_sign(ui->encrypted_file_name, NULL, &buffer, &total_len, srvprvkey);
	
	}else{
		fprintf(stderr, "User %s has version %u, updated version is %u and this is not possible\n", user, ui->key_version, ui->updated_key_version);
		close(new_socket_fd);
		close_db(db);
		pthread_mutex_unlock(mutex);
		exit(1);
	}
	
	send_data(new_socket_fd, buffer, total_len);
  close(new_socket_fd);
	close_db(db);
	pthread_mutex_unlock(mutex); // Is it necessary to pot it here?

  free(ui);
  free(user);
  free(buffer);
	
  return NULL;
}

void *key_authority_routine(void* arg){

	pthread_mutex_t* mutex;
	char* user = "kevin"; // This thread takes care only of kevin
	char* policy = "Audi_v_0 and year_v_0 = 2017";
	char* to_encrypt = "to_send.pdf";
	char* cltpubkey = "cltpubkey.pem";
	char* new_attribute_set;
	char* new_regex_version_buffer;
	char* old_regex_version_buffer;
	uint32_t new_version;
	user_info* ui = NULL;
	bswabe_pub_t* pub;
	
	mutex = (pthread_mutex_t*)arg;	
	
	while(TRUE){
		pthread_mutex_lock(mutex);
		
		open_db(&db);
		fprintf(stdout, "Fin qui tutto bene\n");
		get_user_info(db, user, &ui);
		fprintf(stdout, "Fin qui tutto bene\n");
		if(ui == NULL){
			pthread_mutex_unlock(mutex);
			close_db(db);
			return 0;
		}
		
		fprintf(stdout, "Encrypted decryption key name: %s, Encrypted file name: %s ", ui->encryped_decryption_key_name, ui->encrypted_file_name);
		fprintf(stdout, " Key version: %u, Updated key version: %u, Ciphertext version: %u, Updateted ciphertext version: %u\n", ui->key_version, ui->updated_key_version, ui->ciphertext_version, ui->updated_ciphertext_version);
		fprintf(stdout, "Current attribute set: %s\n", ui->current_attribute_set);
		
		// Check whether attribute set version is consistent
		get_policy_or_attribute_version(ui->current_attribute_set, VERSION_REGEX, &new_version);
		if(new_version != ui->updated_key_version){
			fprintf(stderr, "Database inconsistent\n");
			pthread_mutex_unlock(mutex);
			exit(1);
		}
		
		make_version_regex(new_version, &old_regex_version_buffer);
		new_version++;
		make_version_regex(new_version, &new_regex_version_buffer);
		fprintf(stdout, "New version buffer: %s (%lu bytes)\n", new_regex_version_buffer, strlen(new_regex_version_buffer));
		fprintf(stdout, "Old version buffer: %s (%lu bytes)\n", old_regex_version_buffer, strlen(old_regex_version_buffer));
		
		new_attribute_set = str_replace(ui->current_attribute_set, old_regex_version_buffer, new_regex_version_buffer);
		fprintf(stdout, "Updated attribute set: %s (%lu bytes)\n", new_attribute_set, strlen(new_attribute_set));
		
		if(!update_attribute_set(db, user, new_attribute_set) || !update_version(db, user, UPDATED_KEY_VERSION, new_version)){
			fprintf(stderr, "Could not udate database\n");
			pthread_mutex_unlock(mutex);
			exit(1);
		}
		
		pub = bswabe_pub_unserialize(suck_file(pub_file), 1);
		
		bswabe_keygen_bis(new_attribute_set, msk_file, pub, ui->encryped_decryption_key_name); // Use the same file also for clear decryption key befor it is encrypted
		seal(cltpubkey, ui->encryped_decryption_key_name); // cltpubkey may be put into database as well
		
		fprintf(stdout, "Old policy: %s (%lu bytes)\n", policy, strlen(policy));
		policy = str_replace(policy, old_regex_version_buffer, new_regex_version_buffer);
		fprintf(stdout, "Updated policy: %s (%lu bytes)\n", policy, strlen(policy));
  	bswabe_enc(pub, to_encrypt, ui->encrypted_file_name, parse_policy_lang(policy), 1);
		
		close_db(db);
		
		pthread_mutex_unlock(mutex);
		
		fprintf(stdout, "Key Authority Thread sleeps\n");
		usleep(10000000);
	}
}

void signal_handler() { // Explicit clean-up
	fprintf(stdout, " <-- Signal handler invoked\n");
	close(socket_fd);
  exit(1);
}
