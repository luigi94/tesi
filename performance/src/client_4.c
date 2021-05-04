#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>	
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>
#include <sys/time.h>

#include "seabrew.h"
#include "common.h"

#include "util.h"
#include "shared.h"
#include "parameters.h"

ssize_t nbytes;
int socket_fd;	

char* received_file = "vim-runtime_2\%3a8.1.2269-1ubuntu5_all.deb.sgnd.cpabe.sgnd";
char* ciphertext_file = "vim-runtime_2\%3a8.1.2269-1ubuntu5_all.deb.sgnd.cpabe";
char* plaintext_file = "vim-runtime_2\%3a8.1.2269-1ubuntu5_all.deb";
char* pub_file = "pub_key";
char* prv_file = "blue_vehicle_priv_key";
char* d_file = "blue_vehicle_priv_key.d";
char* pubkey_file_name = "srvpubkey.pem";
char* results_file_name = "Scenario_4.csv";

void recv_data(unsigned char* restrict* const restrict data_buf, const unsigned long* const restrict data_size){
	unsigned long remaining_data;
	unsigned long pointer;
	size_t count;
	ssize_t nbytes;
	
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


void signal_handler();

void read_cp_from_buffer(unsigned char* cp, GByteArray** cph_buf, int* file_len, GByteArray** aes_buf ){
	int i;
	int len;
	int pointer;

	*cph_buf = g_byte_array_new();
	*aes_buf = g_byte_array_new();
	pointer = 0;

	/* read real file len as 32-bit big endian int */
	*file_len = 0;
	for( i = 3; i >= 0; i-- ){
		*file_len |= cp[pointer]<<(i*8);
		pointer++;
	}

	/* read aes buf */
	len = 0;
	for( i = 3; i >= 0; i-- ){
		len |= cp[pointer]<<(i*8);
		pointer++;
	}
	g_byte_array_set_size(*aes_buf, len);
	memcpy((*aes_buf)->data, (void*)(cp + pointer), (size_t)len);
	pointer += len;

	/* read cph buf */
	len = 0;
	for( i = 3; i >= 0; i-- ){
		len |= cp[pointer]<<(i*8);
		pointer++;
	}
	g_byte_array_set_size(*cph_buf, len);
	memcpy((*cph_buf)->data, (void*)(cp + pointer), (size_t)len);
}

int main(int argc, char *argv[]) {
	char server_name[SERVER_NAME_LEN_MAX + 1] = { 0 };
	int server_port;
	struct hostent *server_host;
	struct sockaddr_in server_address;
	
	unsigned char* data_buf;
	unsigned long data_size;
	
	unsigned char* d_buf;
	unsigned long d_size;
	
	uint8_t type;
	
	unsigned long pointer;
	
	size_t iteration;
	struct timeval start;
	struct timeval end;
	FILE* f_results;
	
	seabrew_bswabe_pub_t* pub;
	seabrew_bswabe_cph_t* cph;
	seabrew_bswabe_prv_t* prv;
	
	GByteArray* aes_buf;
	GByteArray* plt;
	GByteArray* cph_buf;
	int file_len;
	unsigned long plt_len;
	element_t m;
		
	seabrew_bswabe_d_t* d;
	
	if(FALSE){
		pbc_random_set_deterministic(0);
	}

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
		
		// Get response type
		memcpy((void*)&type, (void*)(data_buf + pointer), (size_t)TYPE_LEN);
		pointer += (unsigned long) TYPE_LEN;
		
		pub = seabrew_bswabe_pub_unserialize(suck_file(pub_file), 1);
		
		if(type == 0){
			d_size = data_size - pointer;
			if((d_buf = (unsigned char*)malloc(d_size)) == NULL){
				fprintf(stderr, "Error in allocating memory for the partial updates buffer. Error: %s\n", strerror(errno));
				close_socket(socket_fd);
				exit(1);
			}
			
			memcpy((void*)d_buf, (void*)(data_buf + pointer), (size_t)d_size);
			free(data_buf);
			write_file(d_buf, d_size, d_file);
			free(d_buf);
			
			if((d = (seabrew_bswabe_d_t*)malloc(sizeof(seabrew_bswabe_d_t))) == NULL ){
				fprintf(stderr, "Erro in allocating memory for D\n");
				exit(1);
			}
			
			d = seabrew_bswabe_d_unserialize(pub, suck_file(d_file), 1);
			
			seabrew_bswabe_update_dk(prv_file, d);
			
			seabrew_bswabe_d_free(d);
			free(d);
			
			recv_data(&data_buf, &data_size);
			verify(data_buf, &data_size, pubkey_file_name);
			pointer = (unsigned long) LENGTH_FIELD_LEN;
			
			// Get response type
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
		
		prv = seabrew_bswabe_prv_unserialize(pub, suck_file(prv_file), 1);
		
		read_cp_from_buffer(data_buf + pointer, &cph_buf, &file_len, &aes_buf);
		free(data_buf);
		
		cph = seabrew_bswabe_cph_unserialize(pub, cph_buf, 1);
		
		if( !seabrew_bswabe_dec(pub, prv, cph, m) )
			die("%s", bswabe_error());
		seabrew_bswabe_cph_free(cph);
		free(cph);

		plt = aes_128_cbc_decrypt(aes_buf, m);
		g_byte_array_set_size(plt, file_len);
		g_byte_array_free(aes_buf, 1);
		
		plt_len = (unsigned long)plt->len;
		verify(plt->data, &plt_len, pubkey_file_name);
		write_file(plt->data, plt_len, plaintext_file);
		g_byte_array_free(plt, 1);
			
		element_clear(m);
		
		seabrew_bswabe_prv_free(prv);
		free(prv);
		
		seabrew_bswabe_pub_free(pub);
		free(pub);
		
		if(gettimeofday(&end, NULL) != 0){
			fprintf(stderr, "Error in gettimeofday() [end]. Error: %s\n", strerror(errno));
			exit(1);
		}
		fprintf(f_results, "%lu, %lu\n", iteration + 1UL, (unsigned long) ((end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec));
		
		close_socket(socket_fd);
	}
	
	fclose(f_results);
	
	return 0;
}
void signal_handler() { // Explicit clean-up
	fprintf(stdout, "Signal handler invoked\n");
	close_socket(socket_fd);
  exit(1);
}
