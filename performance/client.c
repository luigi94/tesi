#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>	

#include "messages.h"

#define SERVER_NAME_LEN_MAX 255
#define MAX_BUF 1<<16
#define UPDATES_LEN 260

ssize_t nbytes;

int receive_type(uint16_t *num, int fd)
{
	uint16_t ret;
	char *data = (char*)&ret;
	int left = sizeof(ret);
	int rc;
	do {
		rc = recv(fd, data, left, 0);
		if (rc <= 0) { /* instead of ret */
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
				  // use select() or epoll() to wait for the socket to be readable again
			}
			else if (errno != EINTR) {
				  return -1;
			}
		}
		else {
		  data += rc;
		  left -= rc;
		}
	}
	while (left > 0);
	*num = ntohs(ret);
	return 0;
}

int main(int argc, char *argv[]) {
	char server_name[SERVER_NAME_LEN_MAX + 1] = { 0 };
	int server_port, socket_fd;
	struct hostent *server_host;
	struct sockaddr_in server_address;
	size_t username_size;
	char* user;
	
	char* file_buffer;
	char* updates_buffer;
	char file_size_buf[8];
	long file_size;			/* Size of file, in bytes.  */
	long remaining_data;
	FILE* f;
	FILE* f_updates;
	char* received_file = "received.pdf";
	char* updates_file = "partial_updates_received";
	uint16_t type;

	/* Get server name from command line arguments or stdin. */
	if (argc > 1) {
		strncpy(server_name, argv[1], SERVER_NAME_LEN_MAX);
	} else {
		printf("Enter Server Name: ");
		scanf("%s", server_name);
	}

	/* Get server port from command line arguments or stdin. */
	server_port = argc > 3 ? atoi(argv[2]) : 0;
	if (!server_port) {
		printf("Enter Port: ");
		scanf("%d", &server_port);
	}
	if((user = (char*)malloc(MAX_USER_LENGTH)) == NULL){
		printf("CLIENT - Error in allocating memory for username\n");
		exit(0);
	}
	strncpy(user, argv[3], MAX_USER_LENGTH);
	user[MAX_USER_LENGTH - 1] = '\0';
	username_size = strlen(user);
	printf("CLIENT - ID is %s (%lu bytes)\n", user, username_size);
	
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
		exit(1);
	}

	/* Connect to socket with server address. */
	if (connect(socket_fd, (struct sockaddr *)&server_address, sizeof server_address) == -1) {
		perror("connect");
		exit(1);
	}

	/* TODO: Put server interaction code here. For example, use
	 * write(socket_fd,,) and read(socket_fd,,) to send and receive messages
	 * with the client.
	 */
	if((nbytes = send(socket_fd, (void*)&username_size, sizeof(size_t), 0)) < sizeof(size_t)){
		if(nbytes < 0) perror("CLIENT - Failed to username length");
		else printf("CLIENT - Username length not entirely sent\n");
		exit(0);
	}
	if((nbytes = send(socket_fd, (void*)user, strlen(user), 0)) < strlen(user)){
		if(nbytes < 0) perror("CLIENT - Failed to send user");
		else printf("CLIENT - Username not entirely sent\n");
		exit(1);
	}
	
	receive_type(&type, socket_fd);
	printf("Response type: %d\n", type);
	
	switch(type){
		case 0:
			if((updates_buffer = (char*)malloc(UPDATES_LEN)) == NULL){
				printf("Error in allocating memory for the updates to be received\n");
				exit(1);
			}
			if((nbytes = recv(socket_fd, updates_buffer, UPDATES_LEN, 0)) < UPDATES_LEN){
				printf("CLIENT - Received %ld bytes for the updates\n", nbytes);
				if(nbytes < 0){
					printf("CLIENT - Error in receiving file from socket %d\b", socket_fd);
					exit(1);
				}
				//nbytes < sizeof(ric) but > 0
				if(nbytes > 0){
					printf("CLIENT - Error in request format on socket %d on receiving file\n", socket_fd);
					exit(1);
				}
			}
			if((f_updates = fopen(updates_file, "w")) == NULL){
				printf("CLIENT - Error in creating file for updates\n");
				exit(1);
			}
			fwrite(updates_buffer, 1, UPDATES_LEN, f_updates);
			free(updates_buffer);
			fclose(f_updates);
		case 1:
			if((nbytes = recv(socket_fd, (void*)file_size_buf, 8, 0)) < 8){
				printf("CLIENT - Received %ld bytes on 256 expected for file size\n", nbytes);
				if(nbytes < 0){
					printf("CLIENT - Error in receiving data from socket %d\b", socket_fd);
					exit(1);
				}
				//nbytes < sizeof(ric) but > 0
				if(nbytes > 0){
					printf("CLIENT - Error in request format on socket %d\n", socket_fd);
					exit(1);
				}
			}
			
			file_size = atol(file_size_buf);
			fprintf(stdout, "File size : %ld\n", file_size);
			
			if((f = fopen(received_file, "w")) == NULL){
				printf("CLIENT - Error in creating file\n");
				exit(1);
			}
			
			if((file_buffer = (char*)malloc((size_t)file_size)) == NULL){
				printf("Error in allocating memory for the file to be received\n");
				exit(1);
			}
			remaining_data = file_size;
			while(remaining_data > 0){
				if((nbytes = recv(socket_fd, file_buffer, MAX_BUF<remaining_data?MAX_BUF:remaining_data, 0)) < (MAX_BUF<remaining_data?MAX_BUF:remaining_data)){
					printf("CLIENT - Received %ld bytes for file\n", nbytes);
					if(nbytes < 0){
						printf("CLIENT - Error in receiving file from socket %d\b", socket_fd);
						exit(1);
					}
					//nbytes < sizeof(ric) but > 0
					if(nbytes > 0){
						printf("CLIENT - Error in request format on socket %d on receiving file\n", socket_fd);
						exit(1);
					}
				}
				fwrite(file_buffer, 1, MAX_BUF<remaining_data?MAX_BUF:remaining_data, f);
				remaining_data -= nbytes;
				fprintf(stdout, "CLIENT - Received %ld bytes and we hope :- %ld bytes\n", nbytes, remaining_data);
			}
			break;
				
			default:
				printf("CLIENT - Unknown response type\n");
				exit(1);
		}
	
  fclose(f);
	
	close(socket_fd);
	//free(file_buffer);
	return 0;
}
