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
"Usage: seabrew-abe-update-dk [OPTION ...] PRV_KEY D_FILE PUB_KEY\n"
"\n"
"Substitute the D field containted in the private key PRV_KEY\n"
"with that contained in D_FILE, thus updating PRV_KEY.\n"
"\n"
"The new private key is updated up to the version contained in D_FILE.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
"";

char*  prv_file = 0;
char*  d_file = 0;
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
			printf(SEABREW_ABE_VERSION, "-seabrew-update-dk");
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
		else if( !d_file )
		{
			d_file = argv[i];
		}
		else if( !pub_file )
		{
			pub_file = argv[i];
		}
		else
		{
			die(usage);
		}
	if( !pub_file || !d_file || !prv_file )
		die(usage);
}

int
main( int argc, char** argv )
{
	
	seabrew_bswabe_pub_t* pub;
	seabrew_bswabe_d_t* d;
	
	parse_args(argc, argv);
	
	pub = seabrew_bswabe_pub_unserialize(suck_file(pub_file), 1);
	d = seabrew_bswabe_d_unserialize(pub, suck_file(d_file), 1);
	
	seabrew_bswabe_update_dk(prv_file, d);
	
	seabrew_bswabe_d_free(d);
	free(d);
	
	seabrew_bswabe_pub_free(pub);
	free(pub);
	
	return 0;
}
