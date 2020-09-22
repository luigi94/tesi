#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <errno.h>	
#include <netinet/tcp.h>

#include "util.h"

#define SERVER_NAME_LEN_MAX 255
#define MAX_USER_LENGTH 64

ssize_t nbytes;
int socket_fd;	

char* cleartext_file = "received.pdf";
char* pubkey_file_name = "srvpubkey.pem";

void close_socket(const int socket_fd){

	/* TODO PUT THIS FUNCTION IN A SHARED HEADER */
	
	struct tcp_info info;
	unsigned tcp_info_len;
	unsigned long now;
	unsigned old;
	
	tcp_info_len = (unsigned) sizeof info;
	
	if(getsockopt(socket_fd, SOL_TCP, TCP_INFO, (void*)&info, &tcp_info_len) != 0){
		fprintf(stderr, "Error on getsockopt(). Error: %s\n", strerror(errno));
		close(socket_fd);
		exit(1);
	}
	fprintf(stdout, "%d unacket packets remaining\n", info.tcpi_unacked);
	old = info.tcpi_unacked;
	now = get_milliseconds();
	while (info.tcpi_unacked > 0){
		if((unsigned long)(get_milliseconds() - now) > 1000000UL){
			fprintf(stdout, "Expired close timeout\n");
			break;
		}
		usleep((useconds_t) 100000);
		if(getsockopt(socket_fd, SOL_TCP, TCP_INFO, (void*)&info, &tcp_info_len) != 0){
			fprintf(stderr, "Error on getsockopt(). Error: %s\n", strerror(errno));
			close(socket_fd);
			exit(1);
		}
		fprintf(stdout, "%d unacket packets remaining\n", info.tcpi_unacked);

		if(old > info.tcpi_unacked){ /* Some acks has arrived, hence other peer is still alive */
			now = get_milliseconds();
		}
		else if(old < info.tcpi_unacked){
			fprintf(stderr, "Remaining acks have increased... what is going on?\n");
		}
	}
	
	if(info.tcpi_unacked > 0){
		fprintf(stderr, "WARNING - Socket will be closed but there are still %d unaked packets\n", info.tcpi_unacked);
	}
	fprintf(stdout, "Closing socket...\n");
	close(socket_fd);
}

void send_username_size(const int socket_fd, const size_t* const restrict username_size){
	nbytes = send(socket_fd, (void*)username_size, sizeof(size_t), 0);
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
	fprintf(stdout, "Received %ld bytes on socket %d for data size\n", nbytes, socket_fd);
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
	
	fprintf(stdout, "Data size = %lu\n", *data_size);
	
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
		fprintf(stdout, "Received %ld bytes for file from socket %d\n", nbytes, socket_fd);
		if(nbytes < 0){
			fprintf(stderr, "Error in receiving file from socket %d. Error: %s\n", socket_fd, strerror(errno));
			close_socket(socket_fd);
			exit(1);
		}
		if((size_t) nbytes < count){
			fprintf(stdout, "WARNING - File not entirely received from socket %d\n", socket_fd);
		}
		remaining_data -= (unsigned long)nbytes;
		pointer += (unsigned long) nbytes;
		fprintf(stdout, "CLIENT - Received %ld bytes. Remaining: %lu bytes\n", nbytes, remaining_data);
	}
	
	fprintf(stdout, "Received %lu bytes\n", pointer);
}

void check_freshness(const unsigned long now, const unsigned long time_stamp){
	fprintf(stdout, "Received time stamp is %lu, current time stamp is %lu\n", time_stamp, now);
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
	
	unsigned char* cleartext_buf;
	unsigned char* data_buf;
	unsigned long data_size;
	unsigned long cleartext_size;
	
	unsigned long pointer;
	
	unsigned long time_stamp;
	unsigned long now;

	if (argc != 4) {
		fprintf(stderr, "USAGE: ./client server_address port_number user\n");
		exit(1);
	}
	
	strncpy(server_name, argv[1], SERVER_NAME_LEN_MAX);
	server_port = atoi(argv[2]);
	
	signal(SIGINT, signal_handler);
	
	if((user = (char*)malloc(MAX_USER_LENGTH)) == NULL){
		fprintf(stderr, "Error in allocating memory for username. Error: %s\n", strerror(errno));
		close_socket(socket_fd);
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
	
	close_socket(socket_fd);
	
	/* I take the current time_stamp before the signature verification 
	because this procedure may take a long time */
	now = (unsigned long)time(NULL);
	
	verify(data_buf, &data_size, pubkey_file_name);
	
	pointer = (unsigned long) LENGTH_FIELD_LEN;
	
	/* Get timestamp and check freshness */
	memcpy((void*)&time_stamp, (void*)(data_buf + pointer), (size_t)TIMESTAMP_LEN);
	check_freshness(now, time_stamp);
	
	pointer += (unsigned long) TIMESTAMP_LEN;
	
	cleartext_size = data_size - pointer;
	if((cleartext_buf = (unsigned char*)malloc(cleartext_size)) == NULL){
		fprintf(stdout, "Error in allocating memory for the ciphertext buffer. Error: %s\n", strerror(errno));
		exit(1);
	}
	fprintf(stdout, "Ciphertext size: %lu\n", cleartext_size);
	memcpy((void*)cleartext_buf, (void*)(data_buf + pointer), cleartext_size);
	
	free(data_buf);
	
	write_file(cleartext_buf, cleartext_size, cleartext_file);
		
	free(cleartext_buf);
	free(user);
	
	return 0;
}
void signal_handler() { // Explicit clean-up
	fprintf(stdout, "Signal handler invoked\n");
	close_socket(socket_fd);
  exit(1);
}
