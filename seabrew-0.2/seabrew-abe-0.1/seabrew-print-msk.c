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
"Usage: seabrew-abe-print-msk MSK PUB\n"
"\n"
"Print the master key MSK.\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help                    print this message\n\n"
" -v, --version                 print version information\n\n"
" -p, --output-public-key FILE  write public key to FILE\n\n"
" -m, --output-master-key FILE  write master secret key to FILE\n\n"
" -d, --deterministic           use deterministic \"random\" numbers\n"
"                               (only for debugging)\n\n"
"";

char* pub_file = 0;
char* msk_file = 0;

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
			printf(SEABREW_ABE_VERSION, "-seabrew-print-msk");
			exit(0);
		}
		else if( !strcmp(argv[i], "-d") || !strcmp(argv[i], "--deterministic") )
		{
			pbc_random_set_deterministic(0);
		}
		else if( !msk_file )
		{
			msk_file = argv[i];
		}
		else if( !pub_file )
		{
			pub_file = argv[i];
		}
		else
			die(usage);
	
	if( !pub_file || !msk_file)
		die(usage);
}

int
main( int argc, char** argv )
{
	seabrew_bswabe_pub_t* pub;
	seabrew_bswabe_msk_t* msk;

	parse_args(argc, argv);
	
	pbc_random_set_deterministic(8);
	
	pub = seabrew_bswabe_pub_unserialize(suck_file(pub_file), 1);
	msk = seabrew_bswabe_msk_unserialize(pub, suck_file(msk_file), 1);
	
	print_seabrew_msk_t(msk);
	
	seabrew_bswabe_msk_free(msk);
	free(msk);
	
	seabrew_bswabe_pub_free(pub);
	free(pub);
	
	return 0;
}
