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

#define BACKLOG 10

ssize_t nbytes;
size_t ret;
int socket_fd;

char* partial_updates_file = "partial_updates";
char* ciphertext_file = "to_send.pdf.cpabe";
char* msk_file = "master_key";
char* pub_file = "pub_key";
char* upd_file = "upd_key";
char* prvkey_file_name = "srvprvkey.pem";

typedef struct pthread_arg_t {
    int new_socket_fd;
    struct sockaddr_in client_address;
} pthread_arg_t;

/* Thread routine to serve connection to client. */
void *pthread_routine(void *arg);

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

void make_buffer_and_sign(const uint8_t type, const char* const restrict ciphertext_file, const char* const restrict partial_updates_file, unsigned char* restrict* const restrict buffer, unsigned long* const total_len, char* const restrict prvkey_file_name){
  FILE* f_ciphertext;
  FILE* f_partial_updates;
  
  unsigned long ciphertext_len;
	unsigned long time_stamp;
	unsigned char* sgnt_buf;
	unsigned long sgnt_size;
	
	unsigned long pointer;
	
	/*
	.---------------------------------------------------------------------------.
	| TOTAL LEN | TIMESTAMP |  TYPE  | PARTIAL UPDATES | CIPHERTEXT | SIGNATURE |
	|  8 BYTES  |  8 BYTES  | 1 BYTE |    260 BYTES    |  VARIABLE  | 512 BYTES |
	|           |           |        |  (IF TYPE IS 0) |		SIZE    |           |
	'---------------------------------------------------------------------------'
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
	
	/* Adding type */
	pointer = *total_len;
	*total_len += (unsigned long)TYPE_LEN;
	if((*buffer = (unsigned char*)realloc(*buffer, *total_len)) == NULL){
		fprintf(stderr, "Error in reallocating memeory for response type. Error: %s\n", strerror(errno));
		exit(1);
	}
	memcpy((void*)(*buffer + pointer), (void*)&type, (size_t)TYPE_LEN);
	
  /* Adding partial updates (if needed) */
	if(partial_updates_file != NULL){
		if((f_partial_updates = fopen(partial_updates_file, "r")) == NULL){
			fprintf(stderr, "Error in opening %s. Error: %s\n", partial_updates_file, strerror(errno));
			exit(1);
		}
		pointer = *total_len;
		*total_len += UPDATES_LEN;
		if((*buffer = (unsigned char*)realloc(*buffer, *total_len)) == NULL){
			fprintf(stderr, "Error in realloc(). Error: %s\n", strerror(errno));
			exit(1);
		}
		if(fread((void*)(*buffer + pointer), 1, UPDATES_LEN, f_partial_updates) < UPDATES_LEN){
			fprintf(stderr, "Error while reading file '%s'. Error: %s\n", partial_updates_file, strerror(errno));
			exit(1);
		}
		fclose(f_partial_updates);
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
		fprintf(stderr, "Error in reallocating memeory. Error: %s\n", strerror(errno));
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

int main(int argc, char *argv[]) {
	int port, new_socket_fd;
	struct sockaddr_in address;
	pthread_attr_t pthread_attr;
	pthread_arg_t *pthread_arg;
	pthread_t pthread;
	socklen_t client_address_len;

	if(argc != 2){
		fprintf(stderr, "Usage: ./server PORT\n");
		exit(1);
	}
	port = atoi(argv[1]);

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
  struct sockaddr_in client_address = pthread_arg->client_address;
  free(arg);
	char* user;
	size_t username_size;
  uint8_t type;
  uint32_t partial_updates_version;
  uint32_t master_key_version;
  uint32_t cph_version;
  bswabe_pub_t* pub;
  unsigned char* buffer;
  unsigned long total_len;
 	
  receive_username_size(new_socket_fd, &username_size);
	if((user = (char*)malloc(username_size)) == NULL){
		fprintf(stderr, "Error in allocating memory for username. Error: %s\n", strerror(errno));
		close(new_socket_fd);
		exit(1);
	}
	
	receive_username(new_socket_fd, user, username_size);
	
	partial_updates_version = get_partial_updates_version(partial_updates_file);
	cph_version = get_cph_version(ciphertext_file);
	master_key_version = get_msk_version(msk_file);
	
	if((pub = (bswabe_pub_t*)malloc(sizeof(bswabe_pub_t))) == NULL){
		fprintf(stderr, "Error in allocating memory for public key. Error: %s\n", strerror(errno));
		close(new_socket_fd);
		exit(1);
	}
	pub = bswabe_pub_unserialize(suck_file(pub_file), 1);
	
	if(partial_updates_version < master_key_version){
		fprintf(stdout, "Updating partial updates ...\n");
		bswabe_update_partial_updates(pub, partial_updates_file, upd_file);
		type = 0;
	}
	else if(partial_updates_version == master_key_version){
		type = 1;
	}
	else{
		fprintf(stderr, "Error - Partial updates version can't be greater than master key version\n");
		close(new_socket_fd);
		exit(1);
	}
	fprintf(stdout, "Type: %hu\n", type);
	if(cph_version < master_key_version){
		fprintf(stdout, "Updating ciphertext ...\n");
		bswabe_update_cp(pub, ciphertext_file, upd_file);
	}
	else if (cph_version > master_key_version){
		fprintf(stderr, "Error - Ciphertext version can't be greater than master key version\n");
		close(new_socket_fd);
		exit(1);
	}
	free(pub);
	
	if(type == 0){
	
		make_buffer_and_sign(type, ciphertext_file, partial_updates_file, &buffer, &total_len, prvkey_file_name);
	
	}else if(type == 1){
		
		make_buffer_and_sign(type, ciphertext_file, NULL, &buffer, &total_len, prvkey_file_name);
	
	}else{
		fprintf(stderr, "Unknown response type\n");
		close(new_socket_fd);
		exit(1);
	}
	
	send_data(new_socket_fd, buffer, total_len);
	
  close(new_socket_fd);
  free(user);
  free(buffer);
	
  return NULL;
}

void signal_handler() { // Explicit clean-up
	fprintf(stdout, " <-- Signal handler invoked\n");
	close(socket_fd);
  exit(1);
}
