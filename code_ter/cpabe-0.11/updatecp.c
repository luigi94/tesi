#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>

#include "bswabe.h"
#include "private.h"
#include "common.h"


char* usage =
"Usage: cpabe-updatecp [OPTION ...] CPH UPD_KEY PUB_KEY\n"
"\n"
"Blindly update the cipher-text CPH using the update key UPD_KEY\n"
"and public key PUB_KEY parameters.\n"
"The new ciphertext is updated up to UPD_KEY's version. \n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
"";

char*  cph_file = 0;
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
			printf(CPABE_VERSION, "-updatedk");
			exit(0);
		}
		else if( !strcmp(argv[i], "-d") || !strcmp(argv[i], "--deterministic") )
		{
			pbc_random_set_deterministic(0);
		}
		else if( !cph_file )
		{
			cph_file = argv[i];
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
	if( !pub_file || !upd_file || !cph_file )
		die(usage);
}

int
main( int argc, char** argv )
{
	
	parse_args(argc, argv);
	
	bswabe_update_cp(pub_file, cph_file, upd_file);
	
	return 0;
}