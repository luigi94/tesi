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
"Usage: seabrew-abe-updatepk [OPTION ...] PUB_KEY U_PK\n"
"\n"
"Substitute the h field containted in the public key PUB_KEY\n"
"with that contained in U_PK, thus updating PUB_KEY.\n"
"\n"
"The new public key is updated up to the version contained in U_PK.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
"";

char*  u_pk_file = 0;
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
			printf(SEABREW_ABE_VERSION, "-seabrew-update-pk");
			exit(0);
		}
		else if( !strcmp(argv[i], "-d") || !strcmp(argv[i], "--deterministic") )
		{
			pbc_random_set_deterministic(0);
		}
		else if( !pub_file )
		{
			pub_file = argv[i];
		}
		else if( !u_pk_file )
		{
			u_pk_file = argv[i];
		}
		else
		{
			die(usage);
		}
	if( !pub_file || !u_pk_file )
		die(usage);
}

int
main( int argc, char** argv )
{
	
	seabrew_bswabe_pub_t* pub;
	seabrew_bswabe_u_pk_t* u_pk;
	
	parse_args(argc, argv);
	
	pub = seabrew_bswabe_pub_unserialize(suck_file(pub_file), 1);
	u_pk = (seabrew_bswabe_u_pk_t*)seabrew_bswabe_u_pk_unserialize(pub, suck_file(u_pk_file), 1);
	
	seabrew_bswabe_update_pk(pub_file, u_pk);
	
	seabrew_bswabe_u_pk_free(u_pk);
	free(u_pk);
	
	seabrew_bswabe_pub_free(pub);
	free(pub);
	
	return 0;
}
