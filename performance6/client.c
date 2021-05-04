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
#include <openssl/crypto.h>

#include "util.h"
#include "shared.h"
#include "parameters.h"

#if SECURITY == 128
#define PUBLIC_KEY_NAME_PREFIX "./../prime256v1_bits_keys/srvpubkey%u.pem"
#elif SECURITY == 192
#define PUBLIC_KEY_NAME_PREFIX "./../secp384r1_bits_keys/srvpubkey%u.pem"
#elif SECURITY == 256
#define PUBLIC_KEY_NAME_PREFIX "./../secp521r1_bits_keys/srvpubkey%u.pem"
#endif
#define KEY_NAME_LEN 64UL

char public_key_name[KEY_NAME_LEN];

ssize_t nbytes;
int socket_fd;	

char* cleartext_file = "linux-libc-dev_5.4.0-70.78_arm64.deb";
char* results_file_name = "Scenario_6.csv";

unsigned long threshold_time = 50000UL;
unsigned threshold_trials = 5U;

void recv_data(const int socket_fd, unsigned char* restrict* const restrict data_buf, const unsigned long* const restrict data_size){
	unsigned long remaining_data;
	unsigned long pointer;
	
	nbytes = recv(socket_fd, (void*)&(*data_size), (size_t)LENGTH_FIELD_LEN, 0);
	if(nbytes < 0){
		fprintf(stderr, "Error in receiving file size from socket %d. Error: %s\n", socket_fd, strerror(errno));
		close_socket(socket_fd);
		exit(1);
	}
	if(nbytes < 8){
		fprintf(stderr, "File size not entirely received from socket %d. Error: %s\n", socket_fd, strerror(errno));
		close_socket(socket_fd);
		exit(1);
	}
	
	if((*data_buf = (unsigned char*)OPENSSL_malloc((size_t)*data_size)) == NULL){
		fprintf(stderr, "Error in allocating memeory for data size buffer. Error: %s\n", strerror(errno));
		exit(1);
	}
	memcpy((void*)*data_buf, (void*)&(*data_size), LENGTH_FIELD_LEN);
	
	remaining_data = *data_size - (unsigned long)LENGTH_FIELD_LEN;
	pointer = (unsigned long) LENGTH_FIELD_LEN;
	while(remaining_data > 0){
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
		remaining_data -= (unsigned long)nbytes;
		pointer += (unsigned long) nbytes;
	}
}

void check_freshness(const unsigned long old_version, const unsigned long version){
	if(old_version != version){
		fprintf(stderr, "Received outdated data\n");
		close_socket(socket_fd);
		exit(1);
	}
}

void signal_handler();

int main(int argc, char *argv[]) {
	char server_name[SERVER_NAME_LEN_MAX + 1] = { 0 };
	int server_port;
	struct hostent *server_host;
	struct sockaddr_in server_address;
	
	unsigned char* cleartext_buf;
	unsigned char* data_buf;
	unsigned long data_size;
	unsigned long tmp;
	unsigned long cleartext_size;
	
	unsigned long verify_time;
	unsigned trials;
	
	unsigned long pointer;
	
	unsigned long old_version = 0UL;
	unsigned long version;
	
	FILE* f_results;
	struct timeval start;
	struct timeval end;
	
	size_t iteration;
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
	
	fprintf(f_results, "Iteration, Request to download time, Trials\n");
	
	i = 1U;
	trials = 0U;
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
		
		recv_data(socket_fd, &data_buf, &data_size);
		tmp = data_size;
		
		close_socket(socket_fd);
		
  	snprintf(public_key_name, KEY_NAME_LEN, PUBLIC_KEY_NAME_PREFIX, i);
		
		start:
		if(gettimeofday(&start, NULL) != 0){
			fprintf(stderr, "Error in gettimeofday() [start]. Error: %s\n", strerror(errno));
			exit(1);
		}
		//"srvpubkey.pem"
		verify(data_buf, &data_size, public_key_name);
		
		if(gettimeofday(&end, NULL) != 0){
			fprintf(stderr, "Error in gettimeofday() [end]. Error: %s\n", strerror(errno));
			exit(1);
		}
		verify_time = (unsigned long) ((end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec);
		
		if(verify_time > threshold_time && trials < threshold_trials){
			data_size = tmp;
			trials++;
			goto start;
		}
#ifdef DEBUG
		fprintf(stdout, "Iteration: %lu | key: %s | time: %lu | trials: %u\n", iteration + 1UL, public_key_name, verify_time, trials);
#endif
		
		fprintf(f_results, "%lu, %lu, %u\n", iteration + 1UL, verify_time, trials);
		trials = 0U;
		
		pointer = (unsigned long) LENGTH_FIELD_LEN;
		
		memcpy((void*)&version, (void*)(data_buf + pointer), (size_t)TIMESTAMP_LEN);
		check_freshness(version, old_version);
		
		pointer += (unsigned long) TIMESTAMP_LEN;
		
		cleartext_size = data_size - pointer;
		if((cleartext_buf = (unsigned char*)malloc(cleartext_size)) == NULL){
			fprintf(stderr, "Error in allocating memory for the ciphertext buffer. Error: %s\n", strerror(errno));
			exit(1);
		}
		memcpy((void*)cleartext_buf, (void*)(data_buf + pointer), cleartext_size);
		
		OPENSSL_free(data_buf);
		
		write_file(cleartext_buf, cleartext_size, cleartext_file);
			
		OPENSSL_free(cleartext_buf);
		
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
