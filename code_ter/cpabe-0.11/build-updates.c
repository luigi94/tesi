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
"Usage: cpabe-build-updates [OPTION ...] PARTIAL_PRV_KEY PUB_KEY PRV_KEY\n"
"\n"
" DA MODIFICARE... PRV_KEY using the update key UPD_KEY and public key PUB_KEY.\n"
"The new decription key is updated up to UPD_KEY's version.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
"";

char*  partial_prv_file = 0;
char*  prv_file = 0;
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
		else if( !partial_prv_file )
		{
			partial_prv_file = argv[i];
		}
		else if( !pub_file )
		{
			pub_file = argv[i];
		}
		else if( !prv_file )
		{
			prv_file = argv[i];
		}
		else
		{
			die(usage);
		}
	if( !prv_file || !partial_prv_file )
		die(usage);
}

int
main( int argc, char** argv )
{
	
	parse_args(argc, argv);
	
	bswabe_update_prv_and_pub_keys(partial_prv_file, pub_file, prv_file);
	
	return 0;
}
