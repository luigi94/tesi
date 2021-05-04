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
"Usage: seabrew-abe-updatedk [OPTION ...] PRV U_DK PUB_KEY\n"
"\n"
"Blindly update the private PRV using the partial update key U_DK\n"
"and public key PUB_KEY parameters.\n"
"\n"
"The new ciphertext is updated up to U_DK's version.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
"";

char*  prv_file = 0;
char*  u_dk_file = 0;
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
			printf(SEABREW_ABE_VERSION, "-seabrew-updatedk");
			exit(0);
		}
		else if( !strcmp(argv[i], "-d") || !strcmp(argv[i], "--deterministic") )
		{
			pbc_random_set_deterministic(0);
		}
		else if( !prv_file )
		{
			prv_file = argv[i];
		}
		else if( !u_dk_file )
		{
			u_dk_file = argv[i];
		}
		else if( !pub_file )
		{
			pub_file = argv[i];
		}
		else
		{
			die(usage);
		}
	if( !pub_file || !u_dk_file || !prv_file )
		die(usage);
}

int
main( int argc, char** argv )
{
	
	seabrew_bswabe_pub_t* pub;
	seabrew_bswabe_u_dk_t* u_dk;
	parse_args(argc, argv);
	fprintf(stdout, "Fin qui tutto bene\n");
	pbc_random_set_deterministic(11);
	fprintf(stdout, "Fin qui tutto bene\n");
	pub = seabrew_bswabe_pub_unserialize(suck_file(pub_file), 1);
	u_dk = (seabrew_bswabe_u_dk_t*)seabrew_bswabe_u_cp_unserialize(pub, suck_file(u_dk_file), 1);
	fprintf(stdout, "Fin qui tutto bene\n");
	seabrew_bswabe_update_dk(pub, prv_file, u_dk);
	
	seabrew_bswabe_u_cp_free((seabrew_bswabe_u_cp_t*)u_dk);
	fprintf(stdout, "Fin qui tutto bene\n");
	seabrew_bswabe_pub_free(pub);
	
	return 0;
}

