#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>	
#include <glib.h>
#include <pbc.h>

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
char* prv_file = "blue_vehicle_priv_key";
char* pubkey_file_name = "srvpubkey.pem";
char* results_file_name = "results.csv";

void send_username_size(const int socket_fd, const size_t* const restrict username_size){
	nbytes = send(socket_fd, (void*)&(*username_size), (size_t)LENGTH_FIELD_LEN, 0);
	if(nbytes < 0){
		fprintf(stderr, "Error in sending unsername size from socket %d. Error: %s\n", socket_fd, strerror(errno));
		close_socket(socket_fd);
		exit(1);
	}
	if((unsigned long) nbytes < sizeof(size_t)){
		fprintf(stderr, "Username size not entirely sent on socket %d. Error: %s\n", socket_fd, strerror(errno));
		close_socket(socket_fd);
		exit(1);
	}
}
void send_username(const int socket_fd, const char* const restrict user, const size_t username_size){
	nbytes = send(socket_fd, (void*)user, username_size, 0);
	if(nbytes < 0){
		fprintf(stderr, "Error in sending unsername from socket %d. Error: %s\n", socket_fd, strerror(errno));
		close_socket(socket_fd);
		exit(1);
	}
	if((unsigned long) nbytes < username_size){
		fprintf(stderr, "Username not entirely sent on socket %d. Error: %s\n", socket_fd, strerror(errno));
		close_socket(socket_fd);
		exit(1);
	}
}
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
	
	if((*data_buf = (unsigned char*)malloc((size_t)*data_size)) == NULL){
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

void check_freshness(const unsigned long now, const unsigned long time_stamp){
	if(now - time_stamp > (unsigned long)FRESHNESS_THRESHOLD){
		fprintf(stderr, "Received data are autodated\n");
		exit(1);
	}
}

void signal_handler();

int main(int argc, char *argv[]) {
	char server_name[SERVER_NAME_LEN_MAX + 1] = { 0 };
	int server_port;
	struct hostent *server_host;
	struct sockaddr_in server_address;
	
	size_t username_size;
	char* user;
	
	unsigned char* partial_updates_buf;
	unsigned char* ciphertext_buf;
	unsigned char* data_buf;
	unsigned long data_size;
	unsigned long ciphertext_size;
	uint8_t type;
	bswabe_pub_t* pub;
	
	unsigned long pointer;
	
	unsigned long time_stamp;
	unsigned long now;
	
	size_t iteration;
	FILE* f_results;

	if (argc != 4) {
		fprintf(stderr, "USAGE: ./client server_address port_number user\n");
		exit(1);
	}
	
	strncpy(server_name, argv[1], SERVER_NAME_LEN_MAX);
	server_port = atoi(argv[2]);
	
	signal(SIGINT, signal_handler);
	
	if((f_results = fopen(results_file_name, "w")) == NULL){
		fprintf(stderr, "Error in opening %s. Error: %s\n", results_file_name, strerror(errno));
		exit(1);
	}
	
	for(iteration = 0UL; iteration < ITERATIONS; ++iteration){
	
		if((user = (char*)malloc(MAX_USER_LENGTH)) == NULL){
			fprintf(stderr, "Error in allocating memory for username. Error: %s\n", strerror(errno));
			close_socket(socket_fd);
			exit(1);
		}
		strncpy(user, argv[3], MAX_USER_LENGTH);
		user[MAX_USER_LENGTH - 1] = '\0';
		username_size = strlen(user);
		
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

		send_username_size(socket_fd, &username_size);

		send_username(socket_fd, user, username_size);
		
		recv_data(socket_fd, &data_buf, &data_size);
		
		/* I take the current time_stamp before the signature verification 
		because this procedure may take a long time */
		now = (unsigned long)time(NULL);
		
		verify(data_buf, &data_size, pubkey_file_name);
		
		pointer = (unsigned long) LENGTH_FIELD_LEN;
		
		/* Get timestamp and check freshness */
		memcpy((void*)&time_stamp, (void*)(data_buf + pointer), (size_t)TIMESTAMP_LEN);
		check_freshness(now, time_stamp);
		
		/* Get response type */
		pointer += (unsigned long) TIMESTAMP_LEN;
		memcpy((void*)&type, (void*)(data_buf + pointer), (size_t)TYPE_LEN);
		pointer += (unsigned long) TYPE_LEN;
		
		if(type == 0){
			if((partial_updates_buf = (unsigned char*)malloc((size_t)UPDATES_LEN)) == NULL){
				fprintf(stderr, "Error in allocating memory for the partial updated buffer. Error: %s\n", strerror(errno));
				exit(1);
			}
			memcpy((void*)partial_updates_buf, (void*)(data_buf + pointer), (size_t)UPDATES_LEN);
			bswabe_update_pub_and_prv_keys_partial(partial_updates_buf, pub_file, prv_file);
			free(partial_updates_buf);
			pointer += (unsigned long) UPDATES_LEN;
			
		} else if(type != 1){
			fprintf(stderr, "Unknown response type\n");
			exit(1);
		}
		/* Here type is 0 or 1 */
		ciphertext_size = data_size - pointer;
		if((ciphertext_buf = (unsigned char*)malloc(ciphertext_size)) == NULL){
			fprintf(stderr, "Error in allocating memory for the ciphertext buffer. Error: %s\n", strerror(errno));
			exit(1);
		}
		memcpy((void*)ciphertext_buf, (void*)(data_buf + pointer), ciphertext_size);
		
		free(data_buf);
		
		if((pub = (bswabe_pub_t*)malloc(sizeof(bswabe_pub_t))) == NULL){
			fprintf(stderr, "Error in allocating memory for public key. Error: %s\n", strerror(errno));
			exit(1);
		}

		pub = bswabe_pub_unserialize(suck_file(pub_file), 1);
		if(!bswabe_dec(pub, prv_file, cleartext_file, ciphertext_buf))
			die("%s", bswabe_error());
			
		close_socket(socket_fd);
			
		free(ciphertext_buf);
		free(pub);
		free(user);
	}
	
	fclose(f_results);
	
	return 0;
}
void signal_handler() { // Explicit clean-up
	fprintf(stdout, "Signal handler invoked\n");
	close_socket(socket_fd);
  exit(1);
}
