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
"Usage: seabrew-abe-extract-pk UPD PUB FILE\n"
"\n"
"Performs first equation of Eq. (8) operations\n"
"\n"
"The output will be written into FILE\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help                    print this message\n\n"
" -v, --version                 print version information\n\n"
" -d, --deterministic           use deterministic \"random\" numbers\n"
"                               (only for debugging)\n\n"
"";

char* upd_file = 0;
char* pub_file = 0;
char* out_file = 0;

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
			printf(SEABREW_ABE_VERSION, "-seabrew-extract-pk");
			exit(0);
		}
		else if( !strcmp(argv[i], "-d") || !strcmp(argv[i], "--deterministic") )
		{
			pbc_random_set_deterministic(0);
		}
		else if(!upd_file)
		{
			upd_file = argv[i];
		}
		else if(!pub_file)
		{
			pub_file = argv[i];
		}
		else if(!out_file)
		{
			out_file = argv[i];
		}
		else
			die(usage);
			
	if(!upd_file || !out_file || !pub_file)
		die(usage);
}

int
main( int argc, char** argv )
{
	seabrew_bswabe_upd_t* upd;
	seabrew_bswabe_u_pk_t* u_pk;
	seabrew_bswabe_pub_t* pub;
	
	parse_args(argc, argv);
	pbc_random_set_deterministic(5532);
	
	pub = seabrew_bswabe_pub_unserialize(suck_file(pub_file), 1);
	upd = seabrew_bswabe_upd_unserialize(pub, suck_file(upd_file), 1);
	
	u_pk = extract_u_pk(upd);
	spit_file(out_file, seabrew_bswabe_u_cp_serialize((seabrew_bswabe_u_cp_t*)u_pk), 1);
	
	seabrew_bswabe_upd_free(upd);
	seabrew_bswabe_u_cp_free((seabrew_bswabe_u_cp_t*)u_pk);
	seabrew_bswabe_pub_free(pub);

	return 0;
}