#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>

#include "common.h"
#include "seabrew.h"

char* usage =
"Usage: seabrew-abe-setup [OPTION ...]\n"
"\n"
"Generate system parameters, a public key, and a master secret key\n"
"for use with seabrew-abe-keygen, seabrew-abe-enc, and seabrew-abe-dec.\n"
"\n"
"Additionally, initialize their versions at 0.\n"
"\n"
"Output will be written to the files \"pub_key\" and \"master_key\"\n"
"unless the --output-public-key or --output-master-key options are\n"
"used.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help                    print this message\n\n"
" -v, --version                 print version information\n\n"
" -p, --output-public-key FILE  write public key to FILE\n\n"
" -m, --output-master-key FILE  write master secret key to FILE\n\n"
" -d, --deterministic           use deterministic \"random\" numbers\n"
"                               (only for debugging)\n\n"
"";

char* pub_file = "pub_key";
char* msk_file = "master_key";

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
			printf(SEABREW_ABE_VERSION, "-seabrew-setup");
			exit(0);
		}
		else if( !strcmp(argv[i], "-p") || !strcmp(argv[i], "--output-public-key") )
		{
			if( ++i >= argc )
				die(usage);
			else
				pub_file = argv[i];
		}
		else if( !strcmp(argv[i], "-m") || !strcmp(argv[i], "--output-master-key") )
		{
			if( ++i >= argc )
				die(usage);
			else
				msk_file = argv[i];
		}
		else if( !strcmp(argv[i], "-d") || !strcmp(argv[i], "--deterministic") )
		{
			pbc_random_set_deterministic(0);
		}
		else
			die(usage);
}

int
main( int argc, char** argv )
{
	seabrew_bswabe_pub_t* pub;
	seabrew_bswabe_msk_t* msk;

	parse_args(argc, argv);
	pbc_random_set_deterministic(2324);

	seabrew_bswabe_setup(&pub, &msk);
	
	spit_file(pub_file, seabrew_bswabe_pub_serialize(pub), 1);
	spit_file(msk_file, seabrew_bswabe_msk_serialize(msk), 1);
	
	seabrew_bswabe_msk_free(msk);
	free(msk);
	
	seabrew_bswabe_pub_free(pub);
	free(pub);

	return 0;
}
