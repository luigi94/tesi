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
"Usage: cpabe-updatemk [OPTION ...] PUB_KEY MASTER_KEY UPD_KEY\n"
"\n"
"Update the MASTER_KEY using the public key PUB_KEY and\n"
"generate an update key UPD_KEY of one version greater than \n"
"MASTER_KEY's.\n"
"If the file passed through UPD_KEY exists and it is valid\n"
"then it will be update accordingly, otherwise it will be\n"
"generated from scratch.\n"
"The first version of UPD_KEY will be, in any case, 1."
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
"";

char*  pub_file = 0;
char*  msk_file = 0;
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
			printf(CPABE_VERSION, "-updatemk");
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
		else if( !msk_file )
		{
			msk_file = argv[i];
		}
		else if( !upd_file )
		{
			upd_file = argv[i];
		}
		else
		{
			die(usage);
		}
		
	if( !pub_file || !msk_file || !upd_file)
		die(usage);
}

int
main( int argc, char** argv )
{
	bswabe_pub_t* pub;
	bswabe_msk_t* msk;
	bswabe_upd_t* upd = NULL;

	parse_args(argc, argv);
	
	pub = bswabe_pub_unserialize(suck_file(pub_file), 1);
	msk = bswabe_msk_unserialize(pub, suck_file(msk_file), 1);
	
	if( access( upd_file, F_OK ) != -1 ){
		upd = bswabe_upd_unserialize(pub, suck_file(upd_file), upd_file, 1);
		unlink(upd_file);	
	}
	unlink(msk_file);
	bswabe_update_mk(&msk, pub, &upd);
	
	spit_file(msk_file, bswabe_msk_serialize(msk), 1);
	spit_file(upd_file, bswabe_upd_serialize(upd), 1);

	return 0;
}
