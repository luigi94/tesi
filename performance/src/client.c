#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>	

#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>

#include "bswabe.h"
#include "common.h"
#include "private.h"

#include "util.h"

#define SERVER_NAME_LEN_MAX 255
#define MAX_USER_LENGTH 64

ssize_t nbytes;
int socket_fd;	

char* cleartext_file = "received.pdf";
char* partial_updates_received = "partial_updates_received";
char* pub_file = "pub_key";
char* prv_file = "kevin_priv_key";
char* pubkey_file_name = "srvpubkey.pem";

void receive_type(int socket_fd, uint8_t *type){
	unsigned char type_buffer;
	nbytes = recv(socket_fd, &type_buffer, 1, 0);
	if (nbytes != 1){
		fprintf(stderr, "Error on receiving type %d. Error: %s\n", socket_fd, strerror(errno));
		close(socket_fd);
		exit(1);
	}
	memcpy((void*)&(*type), (void*)&type_buffer, 1);
}
void send_username_size(int socket_fd, size_t* username_size){
	nbytes = send(socket_fd, (void*)username_size, sizeof(size_t), 0);
	if(nbytes < 0){
		fprintf(stderr, "Error in sending unsername size from socket %d. Error: %s\n", socket_fd, strerror(errno));
		close(socket_fd);
		exit(1);
	}
	if((unsigned long) nbytes < sizeof(size_t)){
		fprintf(stderr, "Username size not entirely sent on socket %d. Error: %s\n", socket_fd, strerror(errno));
		close(socket_fd);
		exit(1);
	}
}
void send_username(int socket_fd, char* user, size_t username_size){
	nbytes = send(socket_fd, (void*)user, username_size, 0);
	if(nbytes < 0){
		fprintf(stderr, "Error in sending unsername from socket %d. Error: %s\n", socket_fd, strerror(errno));
		close(socket_fd);
		exit(1);
	}
	if((unsigned long) nbytes < username_size){
		fprintf(stderr, "Username not entirely sent on socket %d. Error: %s\n", socket_fd, strerror(errno));
		close(socket_fd);
		exit(1);
	}
}
void recv_key_updates(int socket_fd, unsigned char* updates_buffer){
	nbytes = recv(socket_fd, updates_buffer, UPDATES_LEN, 0);
	fprintf(stdout, "Received %ld bytes for the updates\n", nbytes);
	if(nbytes < 0){
		fprintf(stderr, "Error in receiving key updates from socket %d. Error: %s\n", socket_fd, strerror(errno));
		close(socket_fd);
		exit(1);
	}
	if((unsigned long)nbytes < UPDATES_LEN){
		fprintf(stderr, "Key updates not entirely received from socket %d. Error: %s\n", socket_fd, strerror(errno));
		close(socket_fd);
		exit(1);
	}
}
void recv_data_size(int socket_fd, size_t* file_size){
	unsigned char* data_size_buf;

	if((data_size_buf = (unsigned char*)malloc((size_t)8)) == NULL){
		fprintf(stderr, "Error in allocating memeory for data size buffer. Error: %s\n", strerror(errno));
		exit(1);
	}
	
	nbytes = recv(socket_fd, (void*)data_size_buf, 8, 0);
	fprintf(stdout, "Received %ld bytes on socket %d for file size\n", nbytes, socket_fd);
		
	if(nbytes < 0){
		fprintf(stderr, "Error in receiving file size from socket %d. Error: %s\n", socket_fd, strerror(errno));
		close(socket_fd);
		exit(1);
	}
	if(nbytes < 8){
		fprintf(stderr, "File size not entirely received from socket %d. Error: %s\n", socket_fd, strerror(errno));
		close(socket_fd);
		exit(1);
	}
	
	memcpy((void*)&(*file_size), (void*)data_size_buf, 8);
	fprintf(stdout, "File size: %lu\n", *file_size);
	free(data_size_buf);
}
void recv_data(int socket_fd, size_t file_size, unsigned char* file_buffer){
	size_t remaining_data;
	unsigned long pointer;
	
	remaining_data = file_size;
	pointer = 0UL;
	while(remaining_data > 0){
		size_t count = (size_t) (MAX_BUF < remaining_data ? MAX_BUF : remaining_data);
		nbytes = recv(socket_fd, (void*) (file_buffer + pointer), (size_t)count, 0);
		fprintf(stdout, "Received %ld bytes for file from socket %d\n", nbytes, socket_fd);
		if(nbytes < 0){
			fprintf(stderr, "Error in receiving file from socket %d. Error: %s\n", socket_fd, strerror(errno));
			close(socket_fd);
			exit(1);
		}
		if((size_t) nbytes < count){
			fprintf(stdout, "WARNING - File not entirely received from socket %d\n", socket_fd);
			//close(socket_fd);
			//exit(1);
		}
		remaining_data -= (size_t)nbytes;
		pointer += (size_t) nbytes;
		fprintf(stdout, "CLIENT - Received %ld bytes. Remaining: %lu bytes\n", nbytes, remaining_data);
	}
	
	fprintf(stdout, "Received %lu bytes\n", pointer);
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
	unsigned char* file_buffer;
	unsigned long offset;
	size_t file_size;
	size_t ciphertext_size;
	uint8_t type;
	bswabe_pub_t* pub;
	
	unsigned long time_stamp;

	if (argc != 4) {
		fprintf(stderr, "USAGE: ./client server_address port_number user\n");
		exit(1);
	}
	
	strncpy(server_name, argv[1], SERVER_NAME_LEN_MAX);
	server_port = atoi(argv[2]);
	
	signal(SIGINT, signal_handler);
	
	if((user = (char*)malloc(MAX_USER_LENGTH)) == NULL){
		fprintf(stderr, "Error in allocating memory for username. Error: %s\n", strerror(errno));
		close(socket_fd);
		exit(1);
	}
	strncpy(user, argv[3], MAX_USER_LENGTH);
	user[MAX_USER_LENGTH - 1] = '\0';
	username_size = strlen(user);
	fprintf(stdout, "ID is %s (%lu bytes)\n", user, username_size);
	
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
		close(socket_fd);
		exit(1);
	}

	/* Connect to socket with server address. */
	if (connect(socket_fd, (struct sockaddr *)&server_address, sizeof server_address) == -1) {
		perror("connect");
		exit(1);
	}

	send_username_size(socket_fd, &username_size);

	send_username(socket_fd, user, username_size);
	
	receive_type(socket_fd, &type);
	
	fprintf(stdout, "Response type: %hhu\n", type);

	recv_data_size(socket_fd, &file_size);
	
	if((file_buffer = (unsigned char*)malloc(file_size)) == NULL){
		fprintf(stdout, "Error in allocating memory for the file to be received. Error: %s\n", strerror(errno));
		close(socket_fd);
		exit(1);
	}
	
	recv_data(socket_fd, file_size, file_buffer);
	verify(file_buffer, &file_size, pubkey_file_name);
	
	ciphertext_size = file_size - sizeof(unsigned long);
	
	if(type == 0){
		ciphertext_size -= (size_t) UPDATES_LEN;
		if((ciphertext_buf = (unsigned char*)malloc(ciphertext_size)) == NULL){
			fprintf(stdout, "Error in allocating memory for the ciphertext buffer. Error: %s\n", strerror(errno));
			close(socket_fd);
			exit(1);
		}
		memcpy((void*)ciphertext_buf, (void*)file_buffer, ciphertext_size);
		offset = ciphertext_size;
		if((partial_updates_buf = (unsigned char*)malloc((size_t)UPDATES_LEN)) == NULL){
			fprintf(stdout, "Error in allocating memory for the partial updated buffe. Error: %s\n", strerror(errno));
			close(socket_fd);
			exit(1);
		}
		memcpy((void*)partial_updates_buf, (void*)(file_buffer + offset), UPDATES_LEN);
		offset += UPDATES_LEN;
		bswabe_update_pub_and_prv_keys_partial(partial_updates_buf, pub_file, prv_file);
		free(partial_updates_buf);
		
	} else if(type == 1){
		if((ciphertext_buf = (unsigned char*)malloc(ciphertext_size)) == NULL){
			fprintf(stdout, "Error in allocating memory for the ciphertext buffer. Error: %s\n", strerror(errno));
			close(socket_fd);
			exit(1);
		}
		memcpy((void*)ciphertext_buf, (void*)file_buffer, ciphertext_size);
		offset = ciphertext_size;
	
	} else {
		fprintf(stderr, "Unknown response type\n");
		close(socket_fd);
		exit(1);
	}
	
	memcpy((void*)&time_stamp, (void*)(file_buffer + offset), 8);
	offset += 8;
	fprintf(stdout, "Timestamp received: %lu\n", time_stamp);
	
	free(file_buffer);
			
	if((pub = (bswabe_pub_t*)malloc(sizeof(bswabe_pub_t))) == NULL){
		fprintf(stderr, "Error in allocating memory for public key. Error: %s\n", strerror(errno));
		exit(1);
	}
	
	pub = bswabe_pub_unserialize(suck_file(pub_file), 1);
	
	if(!bswabe_dec(pub, prv_file, cleartext_file, ciphertext_buf))
		die("%s", bswabe_error());
	
	free(ciphertext_buf);
	free(pub);
	free(user);
	
	close(socket_fd);
	
	return 0;
}
void signal_handler() { // Explicit clean-up
	fprintf(stdout, "Signal handler invoked\n");
	close(socket_fd);
  exit(1);
}
