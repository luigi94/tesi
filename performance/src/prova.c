#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>

#include "bswabe.h"

#include "common.h"

int
main( int argc, char** argv ){
	bswabe_setup("msk_file", "pub_file");
	return 0;
}
