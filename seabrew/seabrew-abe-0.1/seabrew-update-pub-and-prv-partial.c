#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>

#include "seabrew.h"
#include "common.h"

char* usage =
"Usage: cpabe-build-updates [OPTION ...] PARTIAL_UPDATES PUB_KEY PRV_KEY\n"
"\n"
"Update the public (encryption) key PUB_KEY and the private (decryption)\n"
"key PRV_KEY using the quantities carried by PARTIAL_UPDATES.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
"";

char*  partial_updates = 0;
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
			printf(CPABE_VERSION, "-update-pub-and-prv-partial");
			exit(0);
		}
		else if( !strcmp(argv[i], "-d") || !strcmp(argv[i], "--deterministic") )
		{
			pbc_random_set_deterministic(0);
		}
		else if( !partial_updates )
		{
			partial_updates = argv[i];
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
	if( !prv_file || !partial_updates )
		die(usage);
}

int
main( int argc, char** argv )
{
	
	parse_args(argc, argv);
	
	seabrew_bswabe_update_pub_and_prv_keys_partial(partial_updates, pub_file, prv_file);
	
	return 0;
}
