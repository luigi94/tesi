#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>

#include "seabrew.h"
#include "common.h"

char* usage =
"Usage: seabrew-abe-update-d [OPTION ...] D UPD PUB_KEY\n"
"\n"
"Blindly update the cipher-text CPH using the partial update key U_CP\n"
"and public key PUB_KEY parameters.\n"
"\n"
"The new ciphertext is updated up to U_CP's version.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
"";

char*  d_file = 0;
char*  upd_file = 0;
char*  pub_file = 0;

void
parse_args( int argc, char** argv )
{
	int i;

	for( i = 1; i < argc; i++ )
		if(      !strcmp(argv[i], "-h") || !strcmp(argv[i], "--help") )
		{
			printf("%s", usage);
			exit(0);
		}
		else if( !strcmp(argv[i], "-v") || !strcmp(argv[i], "--version") )
		{
			printf(SEABREW_ABE_VERSION, "-seabrew-updatecp");
			exit(0);
		}
		else if( !strcmp(argv[i], "-d") || !strcmp(argv[i], "--deterministic") )
		{
			pbc_random_set_deterministic(0);
		}
		else if( !d_file )
		{
			d_file = argv[i];
		}
		else if( !upd_file )
		{
			upd_file = argv[i];
		}
		else if( !pub_file )
		{
			pub_file = argv[i];
		}
		else
		{
			die(usage);
		}
	if( !pub_file || !upd_file || !d_file )
		die(usage);
}

int
main( int argc, char** argv )
{
	
	seabrew_bswabe_pub_t* pub;
	seabrew_bswabe_upd_t* upd;
	
	parse_args(argc, argv);
	
	pbc_random_set_deterministic(32323);
	
	pub = seabrew_bswabe_pub_unserialize(suck_file(pub_file), 1);
	upd = seabrew_bswabe_upd_unserialize(pub, suck_file(upd_file), 1);
	
	seabrew_bswabe_update_cp(pub, d_file, upd);
	
	seabrew_bswabe_upd_free(upd);
	free(upd);
	
	seabrew_bswabe_pub_free(pub);
	free(pub);
	
	return 0;
}

