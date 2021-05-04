#include <stdlib.h>
#include <stdio.h>
#include <netinet/tcp.h>
#include <sys/sendfile.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>

#include "shared.h"
#include "parameters.h"
#include "api.h"

void close_socket(const int socket_fd){	
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
	old = info.tcpi_unacked;
	now = get_milliseconds();
	while (info.tcpi_unacked > 0){
		if((unsigned long)(get_milliseconds() - now) > 1000000UL){
			fprintf(stdout, "Expired close timeout\n");
			break;
		}
		if(usleep((useconds_t) 250000) != 0){
			fprintf(stderr, "Error in usleep(). Error: %s\n", strerror(errno));
			exit(1);
		}
		if(getsockopt(socket_fd, SOL_TCP, TCP_INFO, (void*)&info, &tcp_info_len) != 0){
			fprintf(stderr, "Error on getsockopt(). Error: %s\n", strerror(errno));
			close(socket_fd);
			exit(1);
		}

		if(old > info.tcpi_unacked){ /* Some acks has arrived, hence other peer is still alive */
			now = get_milliseconds();
		}
		else if(old < info.tcpi_unacked){
			fprintf(stderr, "Remaining acks have increased... what is going on?\n");
			now = get_milliseconds();
		}
	}
	
	if(info.tcpi_unacked > 0){
		fprintf(stderr, "WARNING - Socket will be closed but there are still %d unaked packets\n", info.tcpi_unacked);
	}
	close(socket_fd);
}

int fetch_public_key(uint8_t* pk, char* public_key_name){
	// Fetching public key (1 on success, 0 on error)
	FILE* f_pub;
	if((f_pub = fopen(public_key_name, "r")) == NULL) {
		fprintf(stderr, "Error in opening file %s. Error: %s\n", public_key_name, strerror(errno));
		return 0;
	}
	
	if(fread(pk, 1UL, CRYPTO_PUBLICKEYBYTES, f_pub)< CRYPTO_PUBLICKEYBYTES){
		fprintf(stderr, "Error while reading file '%s'\n", public_key_name);
		return 0;
	}
	fclose(f_pub);
	
	return 1;
}

int fetch_private_key(uint8_t* sk, char* private_key_name){
	// Fetching private key (1 on success, 0 on error)
	FILE* f_prv;
	if((f_prv = fopen(private_key_name, "r")) == NULL) {
		fprintf(stderr, "Error in opening file %s. Error: %s\n", private_key_name, strerror(errno));
		return 0;
	}
	
	if(fread(sk, 1UL, CRYPTO_SECRETKEYBYTES, f_prv)< CRYPTO_SECRETKEYBYTES){
		fprintf(stderr, "Error while reading file '%s'\n", private_key_name);
		return 0;
	}
	fclose(f_prv);
	
	return 1;
}

void write_file(const unsigned char* const restrict buffer, const size_t data_len, const char* const restrict name){
	FILE* tmp;
	if((tmp = fopen(name, "w")) == NULL){
		fprintf(stderr, "Error in opening %s. Error: %s\n", name, strerror(errno));
		exit(1);
	}
	if(fwrite(buffer, data_len, 1UL, tmp) != 1UL){
		fprintf(stderr, "Error in writing %s. Error: %s\n", name, strerror(errno));
		fclose(tmp);
		exit(1);
	}
	fclose(tmp);
}

unsigned long get_milliseconds(){
	struct timeval now;
	if(gettimeofday(&now, NULL) != 0){
		fprintf(stderr, "Error in gettimeofday(). Error: %s\n", strerror(errno));
		exit(1);
	}
	return (unsigned long) (now.tv_sec * 1000 + now.tv_usec / 1000);
}
