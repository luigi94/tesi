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
"Usage: seabrew-abe-print-prv [OPTION ...] PRV_KEY PUB_KEY\n"
"\n"
"Print the private key PRV_KEY.\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help                    print this message\n\n"
" -v, --version                 print version information\n\n"
" -d, --deterministic           use deterministic \"random\" numbers\n"
"                               (only for debugging)\n\n"
"";

char* pub_file = 0;
char* prv_file = 0;

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
			printf(SEABREW_ABE_VERSION, "-seabrew-print-prv");
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
		else if( !pub_file )
		{
			pub_file = argv[i];
		}
		else
			die(usage);
	
	if( !pub_file || !prv_file)
		die(usage);
}

int
main( int argc, char** argv )
{
	seabrew_bswabe_pub_t* pub;
	seabrew_bswabe_prv_t* prv;
	
	parse_args(argc, argv);
	
	pub = seabrew_bswabe_pub_unserialize(suck_file(pub_file), 1);
	prv = seabrew_bswabe_prv_unserialize(pub, suck_file(prv_file), 1);
	
	print_seabrew_prv_t(prv);
	
	seabrew_bswabe_prv_free(prv);
	free(prv);
	
	seabrew_bswabe_pub_free(pub);
	free(pub);
	
	return 0;
}
