#include <sqlite3.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <unistd.h>
#include <errno.h>
#include <glib.h>
#include <pbc.h>
#include <fcntl.h>

#include "bswabe.h"
#include "private.h"
#include "common.h"
#include "policy_lang.h"
#include "util.h"
#include "db.h"
#include "shared.h"
#include "parameters.h"

#define BACKLOG 10

ssize_t nbytes;
int socket_fd;

sqlite3* db = NULL;

char* msk_file = "master_key";
char* pub_file = "pub_key";
char* srvprvkey = "srvprvkey.pem";
char* policy = "ECU_MODEL_2247_v_0 or (CAR_MODEL_21_v_0 and ECU_MODEL_2248_v_0)"; // ECU_MODEL_2247 or (CAR_MODEL_21 and ECU_MODEL_2248)
char* to_encrypt = "to_send.pdf";
char* cltpubkey = "cltpubkey.pem";
char* user = "blue_vehicle";

typedef struct pthread_arg_t {
    int new_socket_fd;
    struct sockaddr_in client_address;
    pthread_mutex_t* mutex;
} pthread_arg_t;

typedef struct ka_arg_t {
    pthread_mutex_t* mutex;
    pthread_mutex_t* cond_mutex;
    pthread_cond_t* wait_cv;
} ka_arg_t;

/* Thread routine to serve connection to client. */
void *pthread_routine(void *arg);
void *key_authority_routine(void *arg);

/* Signal handler to handle SIGTERM and SIGINT signals. */
void signal_handler();

void send_flag(const int new_socket_fd, const uint8_t* const restrict flag){
	nbytes = send(new_socket_fd, (void*)&(*flag), (size_t)TYPE_LEN, 0);
	if(nbytes < 0){
		fprintf(stderr, "Error in sending flag %hhu on socket %d. Error: %s\n", *flag, new_socket_fd, strerror(errno));
		close_socket(new_socket_fd);
		exit(1);
	}
}

void send_data(const int new_socket_fd, const char* const restrict ready_file_name){
	FILE * tmp;
  long offset;
  unsigned long remaining_data;
  int fd;
  
	tmp = fopen(ready_file_name, "r");
  fseek(tmp, 0L, SEEK_END);
  remaining_data = (unsigned long) ftell(tmp);
  fclose(tmp);
  
  fd = open(ready_file_name, O_RDONLY);
	
	offset = 0L;
	while (remaining_data > 0) {
		size_t count = (size_t) (MAX_BUF < remaining_data ? MAX_BUF : remaining_data);
		nbytes = sendfile(new_socket_fd, fd, &offset, count);
		if(nbytes < 0){
			fprintf(stderr, "Error in sending firmware updates chunk on socket %d. Error: %s\n", new_socket_fd, strerror(errno));
			close_socket(new_socket_fd);
			exit(1);
		}
		/*
		if((size_t) nbytes < count){
			fprintf(stdout, "WARNING - Firmware updates chunk not entirely sent on socket %d\n", new_socket_fd);
		}
		*/
		remaining_data -= nbytes;
	}
	close(fd);
}

void make_encrypted_decryption_key_buffer_and_sign(const char* const restrict enc_key_file, unsigned char* restrict* const restrict buffer, unsigned long* const total_len, char* const restrict prvkey_file_name){
  FILE* f_key;
  
	unsigned long time_stamp;
	unsigned char* sgnt_buf;
	unsigned long sgnt_size;
	unsigned long key_len;
	
	unsigned long pointer;
	
	/*
	.----------------------------------------------------.
	| TOTAL LEN | TIMESTAMP | DECRYPTION KEY | SIGNATURE |
	|  8 BYTES  |  8 BYTES  |    VARIABLE    | 512 BYTES |
	|           |           |      SIZE      |           |
	'----------------------------------------------------'
	*/
	
	/* Allocating memory for total len (it will be updated at the end of this function) */
	if((*buffer = (unsigned char*)malloc((size_t)LENGTH_FIELD_LEN)) == NULL){
		fprintf(stderr, "Error in allocating memory for message total length. Error: %s\n", strerror(errno));
		exit(1);
	}
	*total_len = LENGTH_FIELD_LEN;
	
	/* Adding timestamp */
	time_stamp = 0UL; //(unsigned long)time(NULL);
	pointer = *total_len;
	*total_len += (unsigned long)TIMESTAMP_LEN;
	if((*buffer = (unsigned char*)realloc(*buffer, *total_len)) == NULL){
		fprintf(stderr, "Error in reallocating memory for timestamp. Error: %s\n", strerror(errno));
		exit(1);
	}
	memcpy((void*)(*buffer + pointer), (void*)&time_stamp, (size_t)TIMESTAMP_LEN);
	
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
}

void make_encrypted_file_buffer_and_sign(const char* const restrict ciphertext_file, unsigned char* restrict* const restrict buffer, unsigned long* const total_len, char* const restrict prvkey_file_name){
  FILE* f_ciphertext;
  
  unsigned long ciphertext_len;
	unsigned long time_stamp;
	unsigned char* sgnt_buf;
	unsigned long sgnt_size;
	
	unsigned long pointer;
	
	/*
	.------------------------------------------------.
	| TOTAL LEN | TIMESTAMP | CIPHERTEXT | SIGNATURE |
	|  8 BYTES  |  8 BYTES  |  VARIABLE  | 512 BYTES |
	|           |           |		 SIZE    |           |
	'------------------------------------------------'
	*/
	
	/* Allocating memory for total len (it will be updated at the end of this function) */
	if((*buffer = (unsigned char*)malloc((size_t)LENGTH_FIELD_LEN)) == NULL){
		fprintf(stderr, "Error in allocating memory for message total length. Error: %s\n", strerror(errno));
		exit(1);
	}
	*total_len = LENGTH_FIELD_LEN;
	
	/* Adding timestamp */
	time_stamp = 0UL; //(unsigned long)time(NULL);
	pointer = *total_len;
	*total_len += (unsigned long)TIMESTAMP_LEN;
	if((*buffer = (unsigned char*)realloc(*buffer, *total_len)) == NULL){
		fprintf(stderr, "Error in reallocating memory for timestamp. Error: %s\n", strerror(errno));
		exit(1);
	}
	memcpy((void*)(*buffer + pointer), (void*)&time_stamp, (size_t)TIMESTAMP_LEN);
  
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
}

void initialize_key_authority_thread(pthread_mutex_t* mutex, pthread_mutex_t* cond_mutex, pthread_cond_t* wait_cv){
	pthread_attr_t pthread_attr;
	pthread_t pthread;
	ka_arg_t *pthread_arg;
	
	if ((pthread_arg = (ka_arg_t*)malloc(sizeof(ka_arg_t))) == NULL) {
		perror("malloc");
		exit(1);
	}
	pthread_arg->mutex = mutex;
	pthread_arg->cond_mutex = cond_mutex;
	pthread_arg->wait_cv = wait_cv;
	
	if (pthread_attr_init(&pthread_attr) != 0) {
		perror("pthread_attr_init");
		exit(1);
	}
	if (pthread_attr_setdetachstate(&pthread_attr, PTHREAD_CREATE_DETACHED) != 0) {
		perror("pthread_attr_setdetachstate");
		exit(1);
	}
	if (pthread_create(&pthread, &pthread_attr, key_authority_routine, (void*)pthread_arg) != 0) {
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
	pthread_mutex_t cond_mutex;
	pthread_cond_t wait_cv;
	size_t requests;

	if(argc != 2){
		fprintf(stderr, "Usage: ./server PORT\n");
		exit(1);
	}
	port = atoi(argv[1]);
	
	/* Initialize database */
	if(!initialize_db(db)){
		fprintf(stderr, "Error in initializing database\n");
		exit(1);
	}
	
	if(pthread_mutex_init(&mutex, NULL) != 0){
		fprintf(stderr, "Error in mutex initialization\n");
		exit(1);
	}
	
	if(pthread_mutex_init(&cond_mutex, NULL) != 0){
		fprintf(stderr, "Error in condition mutex initialization\n");
		exit(1);
	}
	
	if(pthread_cond_init(&wait_cv,  NULL) != 0){
		fprintf(stderr, "Error in condition variable initialization\n");
		exit(1);
	}
	
	initialize_key_authority_thread(&mutex, &cond_mutex, &wait_cv);
	
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
	
	requests = 0UL;
	
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

		/* Initialise pthread argument. */
		pthread_arg->new_socket_fd = new_socket_fd;
		pthread_arg->mutex = &mutex;

		/* Create thread to serve connection to client. */
		if (pthread_create(&pthread, &pthread_attr, pthread_routine, (void *)pthread_arg) != 0) {
			perror("pthread_create");
			free(pthread_arg);
			continue;
		}
		if((requests % REQUESTS) == 0){
			if(pthread_cond_signal(&wait_cv)){
				fprintf(stderr, "Error on condition signal. Error: %s\n", strerror(errno));
				exit(1);
			}
		}
		requests++;
	}
	return 0;
}

void *pthread_routine(void *arg) {
	
	pthread_arg_t *pthread_arg = (pthread_arg_t*)arg;
  int new_socket_fd;
  pthread_mutex_t* mutex;
  user_info* ui = NULL;
  
  mutex = pthread_arg->mutex;
  new_socket_fd = pthread_arg->new_socket_fd;
  free(arg);
	
	pthread_mutex_lock(mutex);
	
	if(!open_db_r(&db)){
		fprintf(stderr, "Could not open database\n");
		exit(1);
	}
	
	if(!get_user_info(db, user, &ui)){
		fprintf(stderr, "Could not retrieve user info\n");
		close_db(db);
		exit(1);
	}
	
	if(!close_db(db)){
		fprintf(stderr, "Error in closing database\n");
		exit(1);
	}
	
	if(ui == NULL){
		fprintf(stderr, "User %s not found\n", user);
		close_db(db);
		exit(1);
	}
	
	send_data(new_socket_fd, ui->encrypted_file_name);
	if(ui->key_version < ui->updated_key_version){
		if(!open_db_rw(&db)){
			close_db(db);
			pthread_mutex_unlock(mutex);
			fprintf(stderr, "Could not open database\n");
			exit(1);
		}
		if(!update_version(db, user, KEY_VERSION, ui->updated_key_version)){
			fprintf(stderr, "Error in updating key version\n");
			close_db(db);
			pthread_mutex_unlock(mutex);
			exit(1);
		}
		if(!close_db(db)){
			pthread_mutex_unlock(mutex);
			exit(1);
		}
		send_flag(new_socket_fd, (uint8_t[]){1});
		send_data(new_socket_fd, ui->encrypted_decryption_key_name);
	}else if(ui->key_version == ui->updated_key_version){
		send_flag(new_socket_fd, (uint8_t[]){0});
	}else{
		fprintf(stderr, "Client decryption key version (%u) is newer than the updated (%u) and thi is not possible\n", ui->key_version, ui->updated_key_version);
		close_db(db);
		pthread_mutex_unlock(mutex);
		exit(1);
	}
	
	pthread_mutex_unlock(mutex); // Is it necessary to pot it here?
	
	close_socket(new_socket_fd);
	
  return NULL;
}

int update_decryption_key_and_re_encrypt_ciphertext(const char* const restrict user){
	char* new_attribute_set;
	char* new_regex_version_buffer;
	char* old_regex_version_buffer;
	uint32_t new_version;
	uint32_t old_version;
	user_info* ui = NULL;
	bswabe_pub_t* pub;
	unsigned char* buffer;
	unsigned long total_len;

	if(!open_db_r(&db)){
		fprintf(stderr, "Could not open database\n");
		exit(1);
	}
	if(!get_user_info(db, user, &ui)){
		if(ui) goto exit_label_1;
		close_db(db);
		return 0;
	}
	
	if(!close_db(db)){
		fprintf(stderr, "Error in closing database\n");
		goto exit_label_4;
	}

	if(ui == NULL){
		goto exit_label_1;
	}

	// Check whether attribute set version is consistent
	get_policy_or_attribute_version(ui->current_attribute_set, VERSION_REGEX, &old_version);
	if(old_version != ui->updated_key_version){
		fprintf(stderr, "Database inconsistent\n");
		goto exit_label_1;
	}

	make_version_regex(old_version, &old_regex_version_buffer);
	new_version = old_version + 1U;
	make_version_regex(new_version, &new_regex_version_buffer);

	new_attribute_set = str_replace(ui->current_attribute_set, old_regex_version_buffer, new_regex_version_buffer);
	
	if(!open_db_rw(&db)){
		fprintf(stderr, "Could not open database\n");
		exit(1);
	}

	if(!update_attribute_set(db, user, new_attribute_set) || !update_version(db, user, UPDATED_KEY_VERSION, new_version)){
		fprintf(stderr, "Could not update database\n");
		goto exit_label_2;
	}
	
	if(!close_db(db)){
		fprintf(stderr, "Error in closing database\n");
		goto exit_label_5;
	}

	ui->updated_key_version = new_version;
	memcpy((void*)ui->current_attribute_set, (void*)new_attribute_set, (strlen(new_attribute_set) > (size_t)MAX_ATTRIBUTE_SET_LEN) ? (size_t) MAX_ATTRIBUTE_SET_LEN : strlen(new_attribute_set));

	if((pub = (bswabe_pub_t*)malloc(sizeof(bswabe_pub_t))) == NULL){
		fprintf(stderr, "Error in allocating memory for public key. Error: %s\n", strerror(errno));
		goto exit_label_5;
	}	
	
	pub = bswabe_pub_unserialize(suck_file(pub_file), 1);

	bswabe_keygen_bis(new_attribute_set, msk_file, pub, ui->encrypted_decryption_key_name);
	seal(cltpubkey, ui->encrypted_decryption_key_name); // cltpubkey may be put into database as well
	make_encrypted_decryption_key_buffer_and_sign(ui->encrypted_decryption_key_name, &buffer, &total_len, srvprvkey);
	write_file(buffer, total_len, ui->encrypted_decryption_key_name);
	free(buffer);
	
	get_policy_or_attribute_version(policy, VERSION_REGEX, &old_version);
	
	if(old_version < new_version){
		policy = str_replace(policy, old_regex_version_buffer, new_regex_version_buffer);
		bswabe_enc(pub, to_encrypt, ui->encrypted_file_name, parse_policy_lang(policy), 1);
		make_encrypted_file_buffer_and_sign(ui->encrypted_file_name, &buffer, &total_len, srvprvkey);
		write_file(buffer, total_len, ui->encrypted_file_name);
		free(buffer);
	}else if (old_version > new_version){
		fprintf(stderr, "Old policy version (%u) is greater than new policy version (%u) and this is not possible. \n", old_version, new_version);
		goto exit_label_3;
	}
	
	goto success;
		
	exit_label_5:
		free(new_regex_version_buffer);
		free(old_regex_version_buffer);
		free(new_attribute_set);
	
	exit_label_4:
		free(ui);
		return 0;
	
	exit_label_3:
		free(pub);
	
	exit_label_2:
		free(new_regex_version_buffer);
		free(old_regex_version_buffer);
		free(new_attribute_set);
	
	exit_label_1:
		free(ui);
		close_db(db);
		return 0;
	
	success:
		return 1;
}

void *key_authority_routine(void* arg){
	ka_arg_t *pthread_arg;
	pthread_mutex_t* mutex;
	pthread_mutex_t* cond_mutex;
	pthread_cond_t* wait_cv;
  
	pthread_arg = (ka_arg_t*)arg;
  mutex = pthread_arg->mutex;
  cond_mutex = pthread_arg->cond_mutex;
  wait_cv = pthread_arg->wait_cv;
  free(arg);
	
	while(TRUE){
		pthread_cond_wait(wait_cv, cond_mutex);
		pthread_mutex_lock(mutex);
		if(!update_decryption_key_and_re_encrypt_ciphertext(user)){
			fprintf(stderr, "Error in key authority thread\n");
			pthread_mutex_unlock(mutex);
			exit(1);
		}
		pthread_mutex_unlock(mutex);
	}
	
	return NULL;
}

void signal_handler() { // Explicit clean-up
	fprintf(stdout, " <-- Signal handler invoked\n");
	close_socket(socket_fd);
  exit(1);
}
