#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/sendfile.h>

#include <netinet/tcp.h>

#include "messages.h"

#define BACKLOG 10
#define MAX_BUF 1<<16
#define UPDATES_LEN 260

ssize_t nbytes;
char* file_to_send = "to_send.pdf";
char* header_file = "partial_updates";

typedef struct pthread_arg_t {
    int new_socket_fd;
    struct sockaddr_in client_address;
    /* TODO: Put arguments passed to threads here. See lines 116 and 139. (22) */
    
} pthread_arg_t;

/* Thread routine to serve connection to client. */
void *pthread_routine(void *arg);

/* Signal handler to handle SIGTERM and SIGINT signals. */
void signal_handler(int signal_number);
int send_type(uint16_t num, int fd)
{
    uint16_t conv = htons(num);
    char *data = (char*)&conv;
    int left = sizeof(conv);
    int rc;
    do {
        rc = send(fd, data, left, 0);
        if (rc < 0) {
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                // use select() or epoll() to wait for the socket to be writable again
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
    return 0;
}
int main(int argc, char *argv[]) {
    int port, socket_fd, new_socket_fd;
    struct sockaddr_in address;
    pthread_attr_t pthread_attr;
    pthread_arg_t *pthread_arg;
    pthread_t pthread;
    socklen_t client_address_len;

    /* Get port from command line arguments or stdin. */
    port = argc > 1 ? atoi(argv[1]) : 0;
    if (!port) {
        printf("Enter Port: ");
        scanf("%d", &port);
    }

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
        /* TODO: Initialise arguments passed to threads here. See lines 22 and
         * 139. (116)
         */

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
    int new_socket_fd = pthread_arg->new_socket_fd;
    struct sockaddr_in client_address = pthread_arg->client_address;
    /* TODO: Get arguments passed to threads here. See lines 22 and 116. (139) */
    free(arg);
		char* user;
		size_t username_size;
		
    int fd;
    char file_size_buf[8];
    struct stat file_stat;
    long offset;
    long remaining_data;
    int yes = 1;
    int no = 0;
    uint16_t type;
    int fd_header;
    
    /* TODO: Put client interaction code here. For example, use
     * write(new_socket_fd,,) and read(new_socket_fd,,) to send and receive
     * messages with the client.
     */	
		if((nbytes = recv(new_socket_fd, (void*)&username_size, sizeof(size_t), 0)) < 0){
			printf("SERVER - Received %ld bytes on %ld expected\n", nbytes, sizeof(size_t));
			if(nbytes < 0){
				printf("SERVER - Error in receiving data from socket %d\b", new_socket_fd);
				exit(0);
			}
			//nbytes < sizeof(ric) but > 0
			if(nbytes > 0){
				printf("SERVER - Error in request format on socket %d\n", new_socket_fd);
				exit(0);
			}
		}
		printf("SERVER - Received %lu bytes for username\n", username_size);
		if((user = (char*)malloc(username_size)) == NULL){
			printf("SERVER - Error in allocating memory for username\n");
			exit(0);
		}
		if((nbytes = recv(new_socket_fd, (void*)user, username_size, 0)) < username_size){
			printf("SERVER - Received %ld bytes on %ld expected\n", nbytes, sizeof(size_t));
			if(nbytes < 0){
				printf("SERVER - Error in receiving data from socket %d\b", new_socket_fd);
				exit(0);
			}
			//nbytes < sizeof(ric) but > 0
			if(nbytes > 0){
				printf("SERVER - Error in request format on socket %d\n", new_socket_fd);
				exit(0);
			}
		}
		printf("SERVER - User is %s (%lu bytes)\n", user, strlen(user));
		
		// SENDING FILE (
		
    /* Open file and get file stats */
    if ((fd = open(file_to_send, O_RDONLY)) == -1) {
		  fprintf(stderr, "Error opening file --> %s", strerror(errno));
		  exit(1);
    }
    if (fstat(fd, &file_stat) < 0) {
		  fprintf(stderr, "SERVER - Error fstat --> %s", strerror(errno));
		  exit(1);
    }
		fprintf(stdout, "File Size: %ld bytes\n", file_stat.st_size);
		sprintf(file_size_buf, "%ld", file_stat.st_size);
		
		/* Open updates file */
    if ((fd_header = open(header_file, O_RDONLY)) == -1) {
		  fprintf(stderr, "Error opening file --> %s", strerror(errno));
		  exit(1);
    }
		
		type = 1; 
		send_type(type, new_socket_fd);
		// INCLUDING HEADER (
		/*
		offset = 0;
  	if((nbytes = sendfile(new_socket_fd, fd_header, &offset, UPDATES_LEN)) < UPDATES_LEN){
			if(nbytes < 0) perror("CLIENT - Failed to send updates");
			else printf("CLIENT - Updates not entirely sent\n");
			exit(1);
  	}
		// )
		*/
		/* Sending file length */
		if((nbytes = send(new_socket_fd, (void*)file_size_buf, sizeof(file_size_buf), 0)) < sizeof(file_size_buf)){
			if(nbytes < 0) perror("CLIENT - Failed to file size\n");
			else printf("CLIENT - File size not entirely sent\n");
			exit(1);
		}
		fprintf(stdout, "SERVER - Sent %ld bytes for the size\n", nbytes);
		printf("Size of long int %ld\n", sizeof(file_stat.st_size));
		
		remaining_data = file_stat.st_size;
		offset = 0;
		
    while (remaining_data > 0) {
    	if((nbytes = sendfile(new_socket_fd, fd, &offset, MAX_BUF<remaining_data?MAX_BUF:remaining_data)) < (MAX_BUF<remaining_data?MAX_BUF:remaining_data)){
				if(nbytes < 0) perror("CLIENT - Failed to file size");
				else printf("CLIENT - File size not entirely sent\n");
				exit(1);
    	}
      fprintf(stdout, "1. Server sent %ld bytes from file's data, offset is now : %ld and remaining data = %ld\n", nbytes, offset, remaining_data);
      remaining_data -= nbytes;
      fprintf(stdout, "2. Server sent %ld bytes from file's data, offset is now : %ld and remaining data = %ld\n", nbytes, offset, remaining_data);
  	}		
		// )
    close(new_socket_fd);
    return NULL;
}

void signal_handler(int signal_number) { // Explicit clean-up
    exit(0);
}
