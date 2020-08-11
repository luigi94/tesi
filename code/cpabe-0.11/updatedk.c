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
"Usage: cpabe-updatedk [OPTION ...] PRV_KEY UPD_KEY PUB_KEY\n"
"\n"
"Update the PRV_KEY using the update key UPD_KEY and public key PUB_KEY.\n"
"The new decription key is updated up to UPD_KEY's version.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
"";

char*  prv_file = 0;
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
		else if( !prv_file )
		{
			prv_file = argv[i];
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
	if( !pub_file || !upd_file || !prv_file )
		die(usage);
}

int
main( int argc, char** argv )
{
	bswabe_prv_t* prv = NULL;
	bswabe_upd_t* upd = NULL;
	bswabe_pub_t* pub = NULL;
	
	parse_args(argc, argv);
	
	pub = bswabe_pub_unserialize(suck_file(pub_file), 1);
	upd = bswabe_upd_unserialize(pub, suck_file(upd_file), 1);
	prv = bswabe_prv_unserialize(pub, suck_file(prv_file), 1);
	unlink(prv_file);
	
	bswabe_update_dk(prv, upd, pub);

	spit_file(prv_file, bswabe_prv_serialize(prv), 1);

	return 0;
}
