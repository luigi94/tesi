#include <stdlib.h>
#include <stdio.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include "shared.h"
#include "util.h"

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
