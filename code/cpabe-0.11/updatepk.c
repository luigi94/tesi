#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>

#include "bswabe.h"
#include "common.h"

char* usage =
"Usage: cpabe-updatepk [OPTION ...] PUB_KEY UPDATE_KEY\n"
"\n"
"Update the public key PUBLIC_KEY using the update key UPDATE_KEY up\n"
"to UPDATE_KEY's version.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
"";

char*  pub_file = 0;
char*  upd_file = 0;

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
			printf(CPABE_VERSION, "-updatepk");
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
		else if( !upd_file )
		{
			upd_file = argv[i];
		}
		else
		{
			die(usage);
		}
		
	if( !pub_file || !upd_file )
		die(usage);
}

int
main( int argc, char** argv )
{
	bswabe_pub_t* pub;
	bswabe_upd_t* upd;

	parse_args(argc, argv);
	
	pub = bswabe_pub_unserialize(suck_file(pub_file), 1);
	
	unlink(pub_file);
	
	upd = bswabe_upd_unserialize(pub, suck_file(upd_file), 1);
	
	bswabe_update_pk(&pub, upd);
	
	spit_file(pub_file, bswabe_pub_serialize(pub), 1);

	return 0;
}
