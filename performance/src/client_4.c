#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>	
#include <glib.h>
#include <pbc.h>
#include <sys/time.h>

#include "bswabe.h"
#include "common.h"
#include "private.h"

#include "util.h"
#include "shared.h"
#include "parameters.h"

ssize_t nbytes;
int socket_fd;	

char* cleartext_file = "vim-runtime_2\%3a8.1.2269-1ubuntu5_all.deb";
char* pub_file = "pub_key";
char* prv_file = "green_vehicle_priv_key";
char* pubkey_file_name = "srvpubkey.pem";
char* results_file_name = "Scenario_4.csv";

void recv_data(unsigned char* restrict* const restrict data_buf, const unsigned long* const restrict data_size){
	unsigned long remaining_data;
	unsigned long pointer;
	size_t count;
	
	remaining_data = (unsigned long)LENGTH_FIELD_LEN;
	pointer = 0UL;
	while(remaining_data > 0){
		count = (size_t) (MAX_BUF < remaining_data ? MAX_BUF : remaining_data);
		nbytes = recv(socket_fd, (void*)(&(*data_size) + pointer), count, 0);
		if(nbytes < 0){
			fprintf(stderr, "Error in receiving file size from socket %d. Error: %s\n", socket_fd, strerror(errno));
			close_socket(socket_fd);
			exit(1);
		}
		/*
		if((size_t) nbytes < (size_t)LENGTH_FIELD_LEN){
			fprintf(stdout, "WARNING - File size not entirely received from socket %d. Error: %s\n", socket_fd, strerror(errno));
		}
		*/
		remaining_data -= (unsigned long)nbytes;
		pointer += (unsigned long) nbytes;
	}
	
	if((*data_buf = (unsigned char*)malloc((size_t)*data_size)) == NULL){
		fprintf(stderr, "Error in allocating memeory for data size buffer. Error: %s\n", strerror(errno));
		close_socket(socket_fd);
		exit(1);
	}
	memcpy((void*)*data_buf, (void*)&(*data_size), LENGTH_FIELD_LEN);
	
	remaining_data = *data_size - (unsigned long)LENGTH_FIELD_LEN;
	pointer = (unsigned long) LENGTH_FIELD_LEN;
	while(remaining_data > 0){
		count = (size_t) (MAX_BUF < remaining_data ? MAX_BUF : remaining_data);
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
	
	unsigned char* data_buf;
	unsigned char* ciphertext_buf;
	unsigned char* partial_updates_buf;
	unsigned long data_size;
	unsigned long ciphertext_size;
	unsigned long partial_updates_size;
	
	uint8_t type;
	bswabe_pub_t* pub;
	
	unsigned long pointer;

	unsigned long ciphertext_version;
	unsigned long old_ciphertext_version = 0UL;
	
	size_t iteration;
	struct timeval start;
	struct timeval end;
	FILE* f_results;

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
	
	fprintf(f_results, "Iteration, Request to decryption time\n");
	
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
		
		if(gettimeofday(&start, NULL) != 0){
			fprintf(stderr, "Error in gettimeofday() [start]. Error: %s\n", strerror(errno));
			exit(1);
		}
		
		recv_data(&data_buf, &data_size);
		verify(data_buf, &data_size, pubkey_file_name);
		
		pointer = (unsigned long) LENGTH_FIELD_LEN;
		
		/* Get response type */
		memcpy((void*)&type, (void*)(data_buf + pointer), (size_t)TYPE_LEN);
		pointer += (unsigned long) TYPE_LEN;
		
		if(type == 0){
			partial_updates_size = data_size - pointer;
			if((partial_updates_buf = (unsigned char*)malloc(partial_updates_size)) == NULL){
				fprintf(stderr, "Error in allocating memory for the partial updates buffer. Error: %s\n", strerror(errno));
				close_socket(socket_fd);
				exit(1);
			}
			memcpy((void*)partial_updates_buf, (void*)(data_buf + pointer), partial_updates_size);
			free(data_buf);
			bswabe_update_pub_and_prv_keys_partial(partial_updates_buf, pub_file, prv_file);
			free(partial_updates_buf);
			
			recv_data(&data_buf, &data_size);
			verify(data_buf, &data_size, pubkey_file_name);
			pointer = (unsigned long) LENGTH_FIELD_LEN;
			
			/* Get response type */
			memcpy((void*)&type, (void*)(data_buf + pointer), (size_t)TYPE_LEN);
			pointer += (unsigned long) TYPE_LEN;
			if(type != 1){
				fprintf(stderr, "Unknown response type\n");
				exit(1);
			}
		
		}else if (type != 1){
			fprintf(stderr, "Unknown response type\n");
			exit(1);
		}
		
		/* Get version and check freshness */
		memcpy((void*)&ciphertext_version, (void*)(data_buf + pointer), (size_t)TIMESTAMP_LEN);
		check_freshness(old_ciphertext_version, ciphertext_version);
		pointer += (unsigned long) TIMESTAMP_LEN;
		
		ciphertext_size = data_size - pointer;
		if((ciphertext_buf = (unsigned char*)malloc(ciphertext_size)) == NULL){
			fprintf(stderr, "Error in allocating memory for the ciphertext buffer. Error: %s\n", strerror(errno));
			close_socket(socket_fd);
			exit(1);
		}
		memcpy((void*)ciphertext_buf, (void*)(data_buf + pointer), ciphertext_size);
		
		free(data_buf);
		
		if((pub = (bswabe_pub_t*)malloc(sizeof(bswabe_pub_t))) == NULL){
			fprintf(stderr, "Error in allocating memory for public key. Error: %s\n", strerror(errno));
			close_socket(socket_fd);
			exit(1);
		}
		pub = bswabe_pub_unserialize(suck_file(pub_file), 1);
		
		if(!bswabe_dec(pub, prv_file, cleartext_file, ciphertext_buf))
			die("%s", bswabe_error());
			
		if(gettimeofday(&end, NULL) != 0){
			fprintf(stderr, "Error in gettimeofday() [end]. Error: %s\n", strerror(errno));
			exit(1);
		}
		fprintf(f_results, "%lu, %lu\n", iteration + 1UL, (unsigned long) ((end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec));
		
		close_socket(socket_fd);
		free(ciphertext_buf);
		free(pub);
	}
	
	fclose(f_results);
	
	return 0;
}
void signal_handler() { // Explicit clean-up
	fprintf(stdout, "Signal handler invoked\n");
	close_socket(socket_fd);
  exit(1);
}
