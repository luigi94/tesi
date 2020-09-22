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
#include <sys/sendfile.h>

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

char* ciphertext_file = "to_send.pdf.cpabe";
char* msk_file = "master_key";
char* pub_file = "pub_key";
char* srvprvkey = "srvprvkey.pem";
char* cltpubkey = "cltpubkey.pem";
char* decryption_key = "kevin_priv_key";
char* encrypted_decription_key = "kevin_priv_key.enc";

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
		fprintf(stdout, "Encrypted key length (from main()) is %lu\n", key_len);
		
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
		memcpy((void*)(*buffer + pointer), (void*)&key_len, (size_t)TYPE_LEN);
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
  unsigned char* buffer;
  unsigned long total_len;
 	
  receive_username_size(new_socket_fd, &username_size);
	if((user = (char*)malloc(username_size)) == NULL){
		fprintf(stderr, "Error in allocating memory for username. Error: %s\n", strerror(errno));
		close(new_socket_fd);
		exit(1);
	}
	
	receive_username(new_socket_fd, user, username_size);
	
	/* TODO
		LOGIC FOR VERSION CHECKING GOES HERE
		ADDITIONALLY, SOME KIND OF ROUTINE SHOULD CARE UPDATING PERIODICALLY DECRIPTION KEY AND ENCRYPT WITH RSA
	*/
	/* This two line of codes have to be executed by another entity, not here */
	seal(cltpubkey, decryption_key);
	unsigned tmp_flag = 0;
	
	if(tmp_flag == 0){
	
		make_buffer_and_sign(ciphertext_file, encrypted_decription_key, &buffer, &total_len, srvprvkey);
	
	}else if(tmp_flag == 1){
		
		make_buffer_and_sign(ciphertext_file, NULL, &buffer, &total_len, srvprvkey);
	
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