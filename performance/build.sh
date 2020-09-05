#!/bin/bash
gcc -Wextra -Wall -O3 -pthread -lnsl -lsocket server.c -o server
gcc -Wextra -Wall -O3 -lnsl -lsocket client.c -o client

