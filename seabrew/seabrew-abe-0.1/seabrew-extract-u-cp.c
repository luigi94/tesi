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
"Usage: seabrew-abe-extract-cp UPD PUB FILE [-r]\n"
"\n"
"Performs Eq. (12) operations\n"
"\n"
"The output will be written into FILE\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help                    print this message\n\n"
" -v, --version                 print version information\n\n"
" -d, --deterministic           use deterministic \"random\" numbers\n"
"                               (only for debugging)\n\n"
" -r, --reset                   reset the content of FILE before writinf\n"
"                               the result\n\n"
"";

char* upd_file = 0;
char* pub_file = 0;
char* out_file = 0;
int reset = 0;

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
			printf(SEABREW_ABE_VERSION, "-seabrew-extract-cp");
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
		else if( !strcmp(argv[i], "-r") || !strcmp(argv[i], "--reset") )
		{
			reset = 1;
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
	seabrew_bswabe_u_cp_t* u_cp;
	seabrew_bswabe_pub_t* pub;
	
	parse_args(argc, argv);
	pbc_random_set_deterministic(4);
	
	pub = seabrew_bswabe_pub_unserialize(suck_file(pub_file), 1);
	upd = seabrew_bswabe_upd_unserialize(pub, suck_file(upd_file), 1);
	
	if( access(out_file, F_OK ) == -1 )
		u_cp = extract_u_cp(upd, NULL, reset);
	else{
		u_cp = extract_u_cp(upd, seabrew_bswabe_u_cp_unserialize(pub, suck_file(out_file), 1), reset);
	}
	spit_file(out_file, seabrew_bswabe_u_cp_serialize(u_cp), 1);
	
	seabrew_bswabe_upd_free(upd);
	seabrew_bswabe_u_cp_free(u_cp);
	seabrew_bswabe_pub_free(pub);

	return 0;
}
