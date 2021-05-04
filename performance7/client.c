#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <sys/time.h>
#include <limits.h>

#include <openssl/crypto.h>

#include "shared.h"
#include "katrng.h"
#include "api.h"

#include "parameters.h"

#if FALCON_MODE == 2
#define PUBLIC_KEY_NAME_PREFIX "./../FALCON512_keys/srvpubkey%u"
#elif FALCON_MODE ==5
#define PUBLIC_KEY_NAME_PREFIX "./../FALCON1024_keys/srvpubkey%u"
#endif

#define KEY_NAME_LEN 64UL

char public_key_name[KEY_NAME_LEN];

ssize_t nbytes;
int socket_fd;	

char* cleartext_file = "vim-runtime_2\%3a8.1.2269-1ubuntu5_all.deb";
char* results_file_name = "Scenario_7.csv";

size_t time_threshold = 150000UL;
size_t trials_threshold = 50UL;

void recv_data(const int socket_fd, unsigned char* restrict* const restrict data_buf, const size_t* const restrict data_size){
	size_t remaining_data;
	unsigned long pointer;
	remaining_data = sizeof(size_t);
	while(remaining_data > 0UL){
		size_t count = (size_t) (MAX_BUF < remaining_data ? MAX_BUF : remaining_data);
		nbytes = recv(socket_fd, (void*) &(*data_size), count, 0);
		if(nbytes < 0){
			fprintf(stderr, "Error in receiving file from socket %d. Error: %s\n", socket_fd, strerror(errno));
			close_socket(socket_fd);
			exit(1);
		}
		/*
		if((size_t) nbytes < count){
			fprintf(stdout, "WARNING - File not entirely received from socket %d\n", socket_fd);
		}
		*/
		remaining_data -= (size_t)nbytes;
		pointer += (size_t) nbytes;
	}
	remaining_data = *data_size;
	if((*data_buf = (unsigned char*)OPENSSL_malloc((size_t)*data_size)) == NULL){
		fprintf(stderr, "Error in allocating memory for data size buffer. Error: %s\n", strerror(errno));
		exit(1);
	}
	memcpy((void*)*data_buf, (void*)&(*data_size), LENGTH_FIELD_LEN);
	
	remaining_data = *data_size;
	pointer = 0UL;
	while(remaining_data > 0UL){
		size_t count = (size_t) (MAX_BUF < remaining_data ? MAX_BUF : remaining_data);
		nbytes = recv(socket_fd, (void*) (*data_buf + pointer), count, 0);
		if(nbytes < 0){
			fprintf(stderr, "Error in receiving file from socket %d. Error: %s\n", socket_fd, strerror(errno));
			close_socket(socket_fd);
			exit(1);
		}
		/*
		if((size_t) nbytes < count){
			fprintf(stdout, "WARNING - File not entirely received from socket %d\n", socket_fd);
		}
		*/
		remaining_data -= (size_t)nbytes;
		pointer += (size_t) nbytes;
	}
}

void check_freshness(const unsigned long old_version, const unsigned long version){
	if(old_version != version){
		fprintf(stderr, "Received outdated data\n");
		exit(1);
	}
}

void signal_handler();

int main(int argc, char *argv[]) {
	char server_name[SERVER_NAME_LEN_MAX + 1] = { 0 };
	int server_port;
	struct hostent *server_host;
	struct sockaddr_in server_address;
	
	unsigned char* data_buf;
	unsigned char* m;
	size_t data_size;
	unsigned long long mlen;
	int ret;
	
	size_t pointer;
	
	unsigned long old_version = 0UL;
	unsigned long version;
	
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
	
	FILE* f_results;
	struct timeval start;
	struct timeval end;
	
	size_t iteration;
	size_t time;
	size_t trials;
	
	unsigned i;

	if (argc != 3) {
		fprintf(stderr, "USAGE: ./client server_address port_number\n");
		exit(1);
	}
	
	strncpy(server_name, argv[1], SERVER_NAME_LEN_MAX);
	server_port = atoi(argv[2]);
	
	signal(SIGINT, signal_handler);
	
	if((f_results = fopen(results_file_name, "w")) == NULL){
		fprintf(stderr, "Error in opening %s. Error: %s\n", results_file_name, strerror(errno));
		exit(1);
	}
	
	fprintf(f_results, "Iteration, Request to download time, Total length, Trials\n");
	
	trials = 0U;
	i = 1U;
	for(iteration = 0UL; iteration < ITERATIONS; ++iteration){
		
		/* Get server host from server name. */
		server_host = gethostbyname(server_name);

		/* Initialise IPv4 server address with server host. */
		memset(&server_address, 0, sizeof server_address);
		server_address.sin_family = AF_INET;
		server_address.sin_port = htons(server_port);
		memcpy(&server_address.sin_addr.s_addr, server_host->h_addr, server_host->h_length);

		/* Create TCP socket. */
		if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
			perror("socket");
			close_socket(socket_fd);
			exit(1);
		}

		/* Connect to socket with server address. */
		if (connect(socket_fd, (struct sockaddr *)&server_address, sizeof server_address) == -1) {
			perror("connect");
			exit(1);
		}
		
		// Receiving data
		recv_data(socket_fd, &data_buf, &data_size);
		close_socket(socket_fd);
		snprintf(public_key_name, KEY_NAME_LEN, PUBLIC_KEY_NAME_PREFIX, i);
		
		label:
		if(gettimeofday(&start, NULL) != 0){
			fprintf(stderr, "Error in gettimeofday() [start]. Error: %s\n", strerror(errno));
			exit(1);
		}
		// Fetching public key and verifying the signature
		if(!fetch_public_key(pk, public_key_name)){
			fprintf(stderr, "Error in fetching public key. Error: %s\n", strerror(errno));
			exit(1);
		}
		
		if((m = (unsigned char*)OPENSSL_malloc(data_size)) == NULL){
			fprintf(stderr, "Error in allocating memory for plain message. Error: %s\n", strerror(errno));
			exit(1);
		}
		
    ret = crypto_sign_open(m, &mlen, data_buf, data_size, pk);
    
    if(mlen > ULONG_MAX){
    	fprintf(stderr, "Message too large\n");
    	exit(1);
    }
		
    if(ret) {
      fprintf(stderr, "Verification failed\n");
      exit(1);
    }
   	
		if(gettimeofday(&end, NULL) != 0){
			fprintf(stderr, "Error in gettimeofday() [end]. Error: %s\n", strerror(errno));
			exit(1);
		}
		time = (size_t) ((end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec);
		if(time > time_threshold && trials < trials_threshold){
			OPENSSL_free(m);
			trials++;
			goto label;
		}
		fprintf(f_results, "%lu, %lu, %lu, %lu\n", iteration + 1UL, time, data_size, trials);
#ifdef DEBUG
		fprintf(stdout, "Iteration: %lu | key: %s | time: %lu | trials: %lu\n", iteration, public_key_name, time, trials);
#endif
   	trials = 0U;
		// Verifying the version
		memcpy((void*)&version, (void*)(m), (size_t)TIMESTAMP_LEN);
		check_freshness(version, old_version);
		
		pointer = (size_t)TIMESTAMP_LEN;
		write_file(m + pointer, mlen - pointer, cleartext_file);
		
		OPENSSL_free(data_buf);
		OPENSSL_free(m);
		
		++i;
	}
	
	fclose(f_results);
	
	return 0;
}
void signal_handler() { // Explicit clean-up
	fprintf(stdout, "Signal handler invoked\n");
	close_socket(socket_fd);
  exit(1);
}
