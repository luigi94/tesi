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
"Usage: seabrew-abe-update-mk [OPTION ...] PUB_KEY MSK_KEY UPD_KEY\n"
"\n"
"Update the MASTER_KEY using the public key PUB_KEY and\n"
"generate an update key UPD_KEY of one version greater than\n"
"MSK_KEY's.\n"
"\n"
"If the UPD_KEY exists and it is validthen the new update\n"
"key will be appended to it, otherwise UPD_KEY will be\n"
"generated from scratch.\n"
"\n"
"The first update key version of UPD_KEY will be, in any case, 1.\n"
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
			printf(SEABREW_ABE_VERSION, "-seabrew-update-mk");
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
	seabrew_bswabe_pub_t* pub;
	seabrew_bswabe_upd_t* upd;
	seabrew_bswabe_upd_t* new_node;
	
	parse_args(argc, argv);
	
	pub = seabrew_bswabe_pub_unserialize(suck_file(pub_file), 1);
	if(access( upd_file, F_OK ) != -1)
		upd = seabrew_bswabe_upd_unserialize(pub, suck_file(upd_file), 1);
	else
		upd = NULL;
		
	new_node = seabrew_bswabe_update_mk(pub, msk_file, upd);
	
	update_file(upd_file, seabrew_bswabe_upd_serialize(new_node), 1);
	
	if(upd){ // The first time update_mk is called upd is null
		seabrew_bswabe_upd_free(upd);
		free(upd);
	}
	
	seabrew_bswabe_upd_free(new_node);
	free(new_node);
	
	seabrew_bswabe_pub_free(pub);
	free(pub);
	
	return 0;
}
