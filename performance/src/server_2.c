#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <sys/sendfile.h>
#include <glib.h>
#include <pbc.h>
#include <fcntl.h>

#include "bswabe.h"
#include "util.h"
#include "shared.h"

#define BACKLOG 10

ssize_t nbytes;
int socket_fd;

char* ciphertext_file = "to_send.pdf.cpabe";
char* msk_file = "master_key";
char* pub_file = "pub_key";
char* srvprvkey = "srvprvkey.pem";

typedef struct pthread_arg_t {
    int new_socket_fd;
    struct sockaddr_in client_address;
    char* file_name;
} pthread_arg_t;

/* Thread routine to serve connection to client. */
void *pthread_routine(void *arg);

/* Signal handler to handle SIGTERM and SIGINT signals. */
void signal_handler();

void send_data(const int new_socket_fd, const char* const restrict ready_file_name){

  long offset;
  unsigned long remaining_data;
  int fd;
  FILE* tmp;
  
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

void make_buffer_and_sign(const char* const restrict ciphertext_file, unsigned char* restrict* const restrict buffer, unsigned long* const total_len, char* const restrict prvkey_file_name){
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
	|           |           |	   SIZE    |           |
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
	
	fseek(f_ciphertext, 0UL, SEEK_END);
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

int main(int argc, char *argv[]) {
	int port, new_socket_fd;
	struct sockaddr_in address;
	pthread_attr_t pthread_attr;
	pthread_arg_t *pthread_arg;
	pthread_t pthread;
	socklen_t client_address_len;
	
	/* This variable will contain file to send */
  unsigned char* buffer;
  unsigned long total_len;
  char* file_name = "ready";	// File ready to be sent

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
	
	make_buffer_and_sign(ciphertext_file, &buffer, &total_len, srvprvkey);
	write_file(buffer, total_len, file_name);
	free(buffer);

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
		pthread_arg->file_name = file_name;

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
  int new_socket_fd;
  char* file_name;
  
  new_socket_fd = pthread_arg->new_socket_fd;
  file_name = pthread_arg->file_name;
  free(arg);

	send_data(new_socket_fd, file_name);
	
  close_socket(new_socket_fd);
	
  return NULL;
}

void signal_handler() { // Explicit clean-up
	fprintf(stdout, " <-- Signal handler invoked\n");
	close_socket(socket_fd);
  exit(1);
}
