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
#include <sys/time.h>

#include "bswabe.h"
#include "common.h"
#include "private.h"
#include "util.h"
#include "shared.h"
#include "parameters.h"

#define BACKLOG 10

ssize_t nbytes;
int socket_fd;
FILE* f_revocation_times;
uint32_t last_key_version_sent = 0U; // Actually a database is needed to handle all vehicles' key

char* partial_updates_file = "green_vehicle_partial_updates";
char* ciphertext_file = "vim-runtime_2\%3a8.1.2269-1ubuntu5_all.deb.cpabe";

char* partial_updates_ready_file = "partial_updates_ready_file";
char* ciphertext_ready_file = "ciphertext_ready_file";

char* msk_file = "master_key";
char* pub_file = "pub_key";
char* upd_file = "upd_key";
char* prvkey_file_name = "srvprvkey.pem";

char* revocation_times_file_name = "revocation_times.csv";

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

void make_partial_update_buffer_and_sign(const uint8_t type, const char* const restrict partial_updates_file, unsigned char* restrict* const restrict buffer, unsigned long* const total_len, char* const restrict prvkey_file_name){
  FILE* f_partial_updates;
  
	unsigned char* sgnt_buf;
	unsigned long sgnt_size;
	
	unsigned long pointer;
	
	/*
	.--------------------------------------------------.
	| TOTAL LEN |  TYPE  | PARTIAL UPDATES | SIGNATURE |
	|  8 BYTES  | 1 BYTE |    260 BYTES    | 512 BYTES |
	'--------------------------------------------------'
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
	
  /* Adding partial updates */
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
	unsigned long version;
	unsigned char* sgnt_buf;
	unsigned long sgnt_size;
	
	unsigned long pointer;
	
	/*
	.---------------------------------------------------------.
	| TOTAL LEN |  VERSION  |  TYPE  | CIPHERTEXT | SIGNATURE |
	|  8 BYTES  |  8 BYTES  | 1 BYTE |  VARIABLE  | 512 BYTES |
	|           |           |        |		SIZE    |           |
	'---------------------------------------------------------'
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
	
	/* Adding version */
	version = 0UL;
	pointer = *total_len;
	*total_len += (unsigned long)TIMESTAMP_LEN;
	if((*buffer = (unsigned char*)realloc(*buffer, *total_len)) == NULL){
		fprintf(stderr, "Error in reallocating memory for timestamp. Error: %s\n", strerror(errno));
		exit(1);
	}
	memcpy((void*)(*buffer + pointer), (void*)&version, (size_t)TIMESTAMP_LEN);
  
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
		
		if((requests % REQUESTS) == 0){
			if(pthread_cond_signal(&wait_cv)){
				fprintf(stderr, "Error on condition signal. Error: %s\n", strerror(errno));
				exit(1);
			}
		}
		requests++;

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
	pthread_mutex_t* mutex;
	uint32_t partial_updates_version;
	
	pthread_arg_t *pthread_arg = (pthread_arg_t *)arg;
  new_socket_fd = pthread_arg->new_socket_fd;
  mutex = pthread_arg->mutex;
  free(arg);
  
  pthread_mutex_lock(mutex);
  partial_updates_version = get_partial_updates_version(partial_updates_file);
  if(last_key_version_sent < partial_updates_version){
  	send_data(new_socket_fd, partial_updates_ready_file);
  	last_key_version_sent = partial_updates_version;
  }
	send_data(new_socket_fd, ciphertext_ready_file);
	
	pthread_mutex_unlock(mutex); 
	
	close_socket(new_socket_fd);
	
  return NULL;
}

void *key_authority_routine(void* arg){
	ka_arg_t *pthread_arg;
	pthread_mutex_t* mutex;
	pthread_mutex_t* cond_mutex;
	pthread_cond_t* wait_cv;
	size_t iteration;
	unsigned char* buffer;
  unsigned long total_len;
	bswabe_pub_t* pub;
	struct timeval start;
	struct timeval end;
  
	pthread_arg = (ka_arg_t*)arg;
  mutex = pthread_arg->mutex;
  cond_mutex = pthread_arg->cond_mutex;
  wait_cv = pthread_arg->wait_cv;
  free(arg);
  iteration = 0UL;
  
	if((pub = (bswabe_pub_t*)malloc(sizeof(bswabe_pub_t))) == NULL){
		fprintf(stderr, "Error in allocating memory for public key. Error: %s\n", strerror(errno));
		exit(1);
	}
	pub = bswabe_pub_unserialize(suck_file(pub_file), 1);
  
  if((f_revocation_times = fopen(revocation_times_file_name, "w")) == NULL){
		fprintf(stderr, "Error in opening %s. Error: %s\n", revocation_times_file_name, strerror(errno));
		exit(1);
	}
	
	fprintf(f_revocation_times, "Iteration, Revocation\n");
	
	while(TRUE){
		pthread_cond_wait(wait_cv, cond_mutex);
		pthread_mutex_lock(mutex);
		if(gettimeofday(&start, NULL) != 0){
			fprintf(stderr, "Error in gettimeofday() [start]. Error: %s\n", strerror(errno));
			exit(1);
		}
		
		bswabe_update_mk(pub, msk_file, upd_file);
		bswabe_update_partial_updates(pub, partial_updates_file, upd_file); //
		bswabe_update_cp(pub, ciphertext_file, upd_file); //
		
		make_partial_update_buffer_and_sign(0, partial_updates_file, &buffer, &total_len, prvkey_file_name);
		write_file(buffer, total_len, partial_updates_ready_file);
		free(buffer);
		
		make_ciphertext_buffer_and_sign(1, ciphertext_file, &buffer, &total_len, prvkey_file_name);
		write_file(buffer, total_len, ciphertext_ready_file);
		free(buffer);
		
		if(gettimeofday(&end, NULL) != 0){
			fprintf(stderr, "Error in gettimeofday() [end]. Error: %s\n", strerror(errno));
			exit(1);
		}
		iteration += 1UL;
		fprintf(f_revocation_times, "%lu, %lu\n", iteration, (unsigned long) ((end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec));
		for(size_t i = 1; i < REQUESTS; ++i){
			iteration += 1UL;
			fprintf(f_revocation_times, "%lu, %lu\n", iteration, 0UL);
		}
		pthread_mutex_unlock(mutex);
	}
	
	fclose(f_revocation_times);
	free(pub);
	
	return NULL;
}

void signal_handler() { // Explicit clean-up
	fprintf(stdout, " <-- Signal handler invoked\n");
	close_socket(socket_fd);
  exit(1);
}
