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
#include <pbc_random.h>
#include <fcntl.h>
#include <sys/time.h>

#include "seabrew.h"
#include "common.h"
#include "util.h"
#include "shared.h"
#include "parameters.h"

#define BACKLOG 10

ssize_t nbytes;
int socket_fd;
FILE* f_revocation_times;
size_t requests;

char* d_file = "blue_vehicle_priv_key.d";
char* d_file_signed = "blue_vehicle_priv_key.d.sgnd";
char* plaintext_file = "vim-runtime_2\%3a8.1.2269-1ubuntu5_all.deb";
char* inner_signed_file = "vim-runtime_2\%3a8.1.2269-1ubuntu5_all.deb.sgnd";
char* ciphertext_file = "vim-runtime_2\%3a8.1.2269-1ubuntu5_all.deb.sgnd.cpabe";
char* ciphertext_ready_file = "vim-runtime_2\%3a8.1.2269-1ubuntu5_all.deb.sgnd.cpabe.sgnd";

char* msk_file = "master_key";
char* pub_file = "pub_key";
char* upd_file = "upd_key";
char* prvkey_file_name = "srvprvkey.pem";

char* revocation_times_file_name = "revocation_times.csv";

typedef struct pthread_arg_t {
    int new_socket_fd;
    struct sockaddr_in client_address;
} pthread_arg_t;

/* Thread routine to serve connection to client. */
void *pthread_routine(void *arg);

/* Signal handler to handle SIGTERM and SIGINT signals. */
void signal_handler();

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

void sign_and_encrypt(){
	unsigned char* buffer;
	size_t plaintext_len;
	unsigned char* sgnt_buf;
	size_t sgnt_len;
	FILE* f_plaintext;
	
	if((f_plaintext = fopen(plaintext_file, "r")) == NULL){
		fprintf(stderr, "Error in opening %s. Error: %s\n", plaintext_file, strerror(errno));
		exit(1);
	}
	
	fseek(f_plaintext, 0UL, SEEK_END);
	plaintext_len = ftell(f_plaintext);
	rewind(f_plaintext);
	
	if((buffer = (unsigned char*)malloc((size_t)(plaintext_len + EXP_SGNT_SIZE))) == NULL){
		fprintf(stderr, "Error in allocating memory for message total length. Error: %s\n", strerror(errno));
		exit(1);
	}
	
	if(fread((void*)buffer, 1UL, plaintext_len, f_plaintext) < plaintext_len){
		fprintf(stderr, "Error while reading file '%s'. Error: %s\n", plaintext_file, strerror(errno));
		exit(1);
	}
	fclose(f_plaintext);
	sign(buffer, plaintext_len, &sgnt_buf, &sgnt_len, prvkey_file_name);
	
	if(sgnt_len != (unsigned long) EXP_SGNT_SIZE){
		fprintf(stderr, "Signature size does not match expected size\n");
		exit(1);
	}
	
	memcpy((void*)(buffer + plaintext_len), (void*)sgnt_buf, sgnt_len);
	
	write_file(buffer, plaintext_len + sgnt_len, inner_signed_file);
	
	if(system("seabrew-abe-enc -k pub_key vim-runtime_2\%3a8.1.2269-1ubuntu5_all.deb.sgnd 'ECU_MODEL_2247 or (CAR_MODEL_21 and ECU_MODEL_2248)'") == -1){
		fprintf(stderr, "Error on system call (0)\n");
		exit(1);
	}
	free(buffer);
	free(sgnt_buf);
}

void make_d_buffer_and_sign(const uint8_t type, const char* const restrict d_file, unsigned char* restrict* const restrict buffer, unsigned long* const total_len, char* const restrict prvkey_file_name){
  FILE* f_d;
  
	unsigned char* sgnt_buf;
	unsigned long sgnt_size;
	
	unsigned long pointer;
	
	/*
	.--------------------------------------------.
	| TOTAL LEN |  TYPE  | {v_DK, D} | SIGNATURE |
	|  8 BYTES  | 1 BYTE | 136 BYTES | 512 BYTES |
	'--------------------------------------------'
	*/
	
	/* Allocating memory for total len (it will be updated at the end of this function) */
	if((*buffer = (unsigned char*)malloc((size_t)LENGTH_FIELD_LEN)) == NULL){
		fprintf(stderr, "Error in allocating memory for message total length. Error: %s\n", strerror(errno));
		exit(1);
	}
	*total_len = LENGTH_FIELD_LEN;
	
	/* Adding type */
	pointer = *total_len;
	*total_len += (unsigned long)TYPE_LEN;
	if((*buffer = (unsigned char*)realloc(*buffer, *total_len)) == NULL){
		fprintf(stderr, "Error in reallocating memeory for response type. Error: %s\n", strerror(errno));
		exit(1);
	}
	memcpy((void*)(*buffer + pointer), (void*)&type, (size_t)TYPE_LEN);
	
  /* Adding D */
	if((f_d = fopen(d_file, "r")) == NULL){
		fprintf(stderr, "Error in opening %s. Error: %s\n", d_file, strerror(errno));
		exit(1);
	}
	pointer = *total_len;
	*total_len += D_LEN;
	if((*buffer = (unsigned char*)realloc(*buffer, *total_len)) == NULL){
		fprintf(stderr, "Error in realloc(). Error: %s\n", strerror(errno));
		exit(1);
	}
	if(fread((void*)(*buffer + pointer), 1, D_LEN, f_d) < D_LEN){
		fprintf(stderr, "Error while reading file '%s'. Error: %s\n", d_file, strerror(errno));
		exit(1);
	}
	fclose(f_d);
	
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

void make_ciphertext_buffer_and_sign(const uint8_t type, const char* const restrict ciphertext_file, unsigned char* restrict* const restrict buffer, unsigned long* const total_len, char* const restrict prvkey_file_name){
  FILE* f_ciphertext;
  
  unsigned long ciphertext_len;
	unsigned char* sgnt_buf;
	unsigned long sgnt_size;
	
	unsigned long pointer;
	
	/*
	.---------------------------------------------.
	| TOTAL LEN |  TYPE  | CIPHERTEXT | SIGNATURE |
	|  8 BYTES  | 1 BYTE |  VARIABLE  | 512 BYTES |
	|           |        |	 SIZE     |           |
	'---------------------------------------------'
	*/
	
	/* Allocating memory for total len (it will be updated at the end of this function) */
	if((*buffer = (unsigned char*)malloc((size_t)LENGTH_FIELD_LEN)) == NULL){
		fprintf(stderr, "Error in allocating memory for message total length. Error: %s\n", strerror(errno));
		exit(1);
	}
	*total_len = LENGTH_FIELD_LEN;
	
	/* Adding type */
	pointer = *total_len;
	*total_len += (unsigned long)TYPE_LEN;
	if((*buffer = (unsigned char*)realloc(*buffer, *total_len)) == NULL){
		fprintf(stderr, "Error in reallocating memeory for response type. Error: %s\n", strerror(errno));
		exit(1);
	}
	memcpy((void*)(*buffer + pointer), (void*)&type, (size_t)TYPE_LEN);
  
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
}

int main(int argc, char *argv[]) {
	int port, new_socket_fd;
	struct sockaddr_in address;
	pthread_attr_t pthread_attr;
	pthread_arg_t *pthread_arg;
	pthread_t pthread;
	socklen_t client_address_len;
	unsigned char* buffer;
	unsigned long total_len;
	
	if(FALSE){
		pbc_random_set_deterministic(0);
	}
	
	if(argc != 2){
		fprintf(stderr, "Usage: ./server PORT\n");
		exit(1);
	}
	
	sign_and_encrypt();
	make_ciphertext_buffer_and_sign(1, ciphertext_file, &buffer, &total_len, prvkey_file_name);
	write_file(buffer, total_len, ciphertext_ready_file);
	free(buffer);
	
	if((f_revocation_times = fopen(revocation_times_file_name, "w")) == NULL){
		fprintf(stderr, "Error in opening %s. Error: %s\n", revocation_times_file_name, strerror(errno));
		exit(1);
	}
	fprintf(f_revocation_times, "Iteration, Revocation\n");
	
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
  int new_socket_fd;
	struct timeval start;
	struct timeval end;
	unsigned char* buffer;
	size_t total_len;

	if(gettimeofday(&start, NULL) != 0){
		fprintf(stderr, "Error in gettimeofday() [start]. Error: %s\n", strerror(errno));
		exit(1);
	}
	
	pthread_arg_t *pthread_arg = (pthread_arg_t *)arg;
  new_socket_fd = pthread_arg->new_socket_fd;
  free(arg);
		
	requests++;
  
	if(((requests - 1UL) % REQUESTS) == 0){
		if(system("seabrew-abe-update-mk pub_key master_key upd_key") == -1){
			fprintf(stderr, "Error on system call (1)\n");
			exit(1);
		}
		if(system("seabrew-abe-update-d blue_vehicle_priv_key.d upd_key pub_key") == -1){
			fprintf(stderr, "Error on system call (2)\n");
			exit(1);
		}
		make_d_buffer_and_sign(0, d_file, &buffer, &total_len, prvkey_file_name);
		write_file(buffer, total_len, d_file_signed);
		free(buffer);
		
		if(system("seabrew-abe-update-cp vim-runtime_2\%3a8.1.2269-1ubuntu5_all.deb.sgnd.cpabe upd_key pub_key") == -1){
			fprintf(stderr, "Error on system call (3)\n");
			exit(1);
		}
		make_ciphertext_buffer_and_sign(1, ciphertext_file, &buffer, &total_len, prvkey_file_name);
		write_file(buffer, total_len, ciphertext_ready_file);
		free(buffer);
		
		if(gettimeofday(&end, NULL) != 0){
			fprintf(stderr, "Error in gettimeofday() [end]. Error: %s\n", strerror(errno));
			exit(1);
		}
		fprintf(f_revocation_times, "%lu, %lu\n", requests, (unsigned long) ((end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec));
		
		send_data(new_socket_fd, d_file_signed);
	}else{
		if(gettimeofday(&end, NULL) != 0){
			fprintf(stderr, "Error in gettimeofday() [end]. Error: %s\n", strerror(errno));
			exit(1);
		}
		
		fprintf(f_revocation_times, "%lu, %lu\n", requests, (unsigned long) ((end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec));
	}
	
	send_data(new_socket_fd, ciphertext_ready_file);
	
	close_socket(new_socket_fd);
	
  return NULL;
}

void signal_handler() { // Explicit clean-up
	fprintf(stdout, " <-- Signal handler invoked\n");
	fclose(f_revocation_times);
	close_socket(socket_fd);
  exit(1);
}
