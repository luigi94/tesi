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

#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>

#include <netinet/tcp.h>

#include "bswabe.h"
#include "common.h"
#include "private.h"

#define BACKLOG 10
#define MAX_BUF 1<<16
#define UPDATES_LEN 260

ssize_t nbytes;
int socket_fd;

char* partial_updates_file = "partial_updates";
char* ciphertext_file = "to_send.pdf.cpabe";
char* msk_file = "master_key";
char* pub_file = "pub_key";
char* upd_file = "upd_key";

typedef struct pthread_arg_t {
    int new_socket_fd;
    struct sockaddr_in client_address;
} pthread_arg_t;

/* Thread routine to serve connection to client. */
void *pthread_routine(void *arg);

/* Signal handler to handle SIGTERM and SIGINT signals. */
void signal_handler();

void send_type(uint16_t num, int new_socket_fd) {
	uint16_t conv = htons(num);
	char *data = (char*)&conv;
	ssize_t left = (ssize_t) sizeof(conv);
	do {
		nbytes = send(new_socket_fd, data, left, 0);
		if (nbytes < 0 && errno != EINTR){
			fprintf(stderr, "Error in sending response type from socket %d. Error: %s\n", new_socket_fd, strerror(errno));
			close(new_socket_fd);
			exit(1);
		}
		else {
		  data += nbytes;
		  left -= nbytes;
		}
	} while (left > 0);
}
void receive_username_size(int new_socket_fd, size_t* username_size){
	ssize_t nbytes;
	nbytes = recv(new_socket_fd, (void*)username_size, (size_t) sizeof(size_t), 0);
	if(nbytes < 0){
		fprintf(stderr, "Error in receiving unsername size from socket %d. Error: %s\n", new_socket_fd, strerror(errno));
		close(new_socket_fd);
		exit(1);
	}
	if((unsigned long) nbytes < sizeof(size_t)){
		fprintf(stderr, "Username size not entirely received on socket %d. Error: %s\n", new_socket_fd, strerror(errno));
		close(new_socket_fd);
		exit(1);
	}
}
void receive_username(int new_socket_fd, char* user, size_t username_size){
	ssize_t nbytes;
	nbytes = recv(new_socket_fd, (void*)user, (size_t) username_size, 0);
	if(nbytes < 0){
		fprintf(stderr, "Error in receiving username from socket %d. Error: %s\n", new_socket_fd, strerror(errno));
		close(new_socket_fd);
		exit(1);
	}
	if((size_t) nbytes < username_size){
		fprintf(stderr, "Username not entirely received on socket %d. Error: %s\n", new_socket_fd, strerror(errno));
		close(new_socket_fd);
		exit(1);
	}
}
void send_updates(int new_socket_fd, char* partial_updates_file){
	ssize_t nbytes;
	int fd_updates;
	
	/* Open updates file */
  if ((fd_updates = open(partial_updates_file, O_RDONLY)) == -1) {
	  fprintf(stderr, "Error in opening updates file %s\n", strerror(errno));
	  close(new_socket_fd);
	  exit(1);
  }
  nbytes = sendfile(new_socket_fd, fd_updates, 0, (size_t) UPDATES_LEN);
	if(nbytes < 0){
		fprintf(stderr, "Error in sending key updates on socket %d. Error: %s\n", new_socket_fd, strerror(errno));
		close(new_socket_fd);
		exit(1);
	}
	
	if((size_t) nbytes < UPDATES_LEN){
		fprintf(stderr, "Key updates not entirely received on socket %d. Error: %s\n", new_socket_fd, strerror(errno));
		close(new_socket_fd);
		exit(1);
	}
}
void send_file(int new_socket_fd, char* to_send){
	ssize_t nbytes;
	int fd;
  long offset;
  long remaining_data;
  char file_size_buf[8];
  struct stat file_stat;
  
  /* Open file */
  if ((fd = open(to_send, O_RDONLY)) == -1) {
	  fprintf(stderr, "Error in opening firmware updates %s\n", strerror(errno));
	  close(new_socket_fd);
	  exit(1);
  }
  /* Get file statistics */
  if (fstat(fd, &file_stat) < 0) {
	  fprintf(stderr, "Error in getting statistics of firmware updates --> %s", strerror(errno));
	  close(new_socket_fd);
	  exit(1);
  }
	fprintf(stdout, "File Size: %ld bytes\n", file_stat.st_size);
	sprintf(file_size_buf, "%ld", file_stat.st_size);
  
	/* Sending file length */
	nbytes = send(new_socket_fd, (void*)file_size_buf, (size_t) sizeof(file_size_buf), 0);
	if(nbytes < 0){
		fprintf(stderr, "Error in sending firmware updates size on socket %d. Error: %s\n", new_socket_fd, strerror(errno));
		close(new_socket_fd);
		exit(1);
	}
	if((unsigned long) nbytes < sizeof(file_size_buf)){
		fprintf(stderr, "Firmware updates size not entirely sent on socket %d. Error: %s\n", new_socket_fd, strerror(errno));
		close(new_socket_fd);
		exit(1);
	}
	fprintf(stdout, "Sent %ld bytes for the firmware updates size\n", nbytes);
	
	offset = 0;
	remaining_data = file_stat.st_size;
	while (remaining_data > 0) {
		size_t count = (size_t) (MAX_BUF < remaining_data ? MAX_BUF : remaining_data);
		nbytes = sendfile(new_socket_fd, fd, &offset, count);
		if(nbytes < 0){
			fprintf(stderr, "Error in sending firmware updates on socket %d. Error: %s\n", new_socket_fd, strerror(errno));
			close(new_socket_fd);
			exit(1);
		}
		if((size_t) nbytes < count){
			fprintf(stderr, "Firmware updates size not entirely sent on socket %d. Error: %s\n", new_socket_fd, strerror(errno));
			close(new_socket_fd);
			exit(1);
		}
		remaining_data -= nbytes;
	}
}
int main(int argc, char *argv[]) {
    int port, new_socket_fd;
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
  free(arg);
	char* user;
	size_t username_size;
  uint16_t type;
  uint32_t partial_updates_version;
  uint32_t master_key_version;
  uint32_t cph_version;
  bswabe_pub_t* pub;
 	
  receive_username_size(new_socket_fd, &username_size);
	if((user = (char*)malloc(username_size)) == NULL){
		fprintf(stderr, "Error in allocating memory for username. Error: %s\n", strerror(errno));
		close(new_socket_fd);
		exit(1);
	}
	
	receive_username(new_socket_fd, user, username_size);
	
	partial_updates_version = get_partial_updates_version(partial_updates_file);
	cph_version = get_cph_version(ciphertext_file);
	master_key_version = get_msk_version(msk_file);
	
	if((pub = (bswabe_pub_t*)malloc(sizeof(bswabe_pub_t))) == NULL){
		fprintf(stderr, "Error in allocating memory for public key. Error: %s\n", strerror(errno));
		close(new_socket_fd);
		exit(1);
	}
	pub = bswabe_pub_unserialize(suck_file(pub_file), 1);
	
	if(partial_updates_version < master_key_version){
		fprintf(stdout, "Updating partial updates ...\n");
		bswabe_update_partial_updates(pub, partial_updates_file, upd_file);
		type = 0;
	}
	else if(partial_updates_version == master_key_version){
		type = 1;
	}
	else{
		fprintf(stderr, "Error - Partial updates version can't be greater that master key version\n");
		close(new_socket_fd);
		exit(1);
	}
	fprintf(stdout, "Type: %hu\n", type);
	if(cph_version < master_key_version){
		fprintf(stdout, "Updating ciphertext ...\n");
		bswabe_update_cp(pub, ciphertext_file, upd_file);
	}
	else if (cph_version > master_key_version){
		fprintf(stderr, "Error - Ciphertext version can't be greater that master key version\n");
		close(new_socket_fd);
		exit(1);
	}
	free(pub);
	send_type(type, new_socket_fd);
	
	switch(type){
		case 0:
			send_updates(new_socket_fd, partial_updates_file);
		
		case 1:
			send_file(new_socket_fd, ciphertext_file);
			break;
			
		default:
			fprintf(stderr, "Unknown response type\n");
			close(new_socket_fd);
			exit(1);
	}
  close(new_socket_fd);
  free(user);
	
  return NULL;
}

void signal_handler() { // Explicit clean-up
	fprintf(stdout, " <-- Signal handler invoked\n");
	close(socket_fd);
  exit(0);
}
