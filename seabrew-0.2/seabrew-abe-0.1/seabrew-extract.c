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
"Usage: seabrew-abe-extract [OPTION ...] UPD PUB FILE [-s START] [-e END]\n"
"\n"
"Extract the update key(s) from version START to version END.\n"
"If neither START nor END are passed, only the last update key\n"
"will be extracted\n"
"If only START is passed, then all the update keys from START\n"
"will be extracted\n"
"\n"
"If only END is passed, then all the update keys up to END\n"
"will be extracted\n"
"\n"
"The output will be written into FILE\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help                    print this message\n\n"
" -v, --version                 print version information\n\n"
" -d, --deterministic           use deterministic \"random\" numbers\n"
"                               (only for debugging)\n\n"
" -s, --start                   the version from which extraction starts\n\n"
" -e, --end                     the version at which extraction ends\n\n"
"";

char* upd_file = 0;
char* pub_file = 0;
char* out_file = 0;
uint32_t start = 0;
uint32_t end = 0;

void
parse_args( int argc, char** argv )
{
	int i;
	int tmp;

	for( i = 1; i < argc; i++ )
		if(      !strcmp(argv[i], "-h") || !strcmp(argv[i], "--help") )
		{
			printf("%s", usage);
			exit(0);
		}
		else if( !strcmp(argv[i], "-v") || !strcmp(argv[i], "--version") )
		{
			printf(SEABREW_ABE_VERSION, "-seabrew-extract");
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
		else if( !strcmp(argv[i], "-s") || !strcmp(argv[i], "--start") )
		{
			if( ++i >= argc )
				die(usage);
			else{
				tmp = atoi(argv[i]);
				if(tmp < 0)
					die("Versions cannot be negative\n");
				start = (uint32_t)tmp;
			}
		}
		else if( !strcmp(argv[i], "-e") || !strcmp(argv[i], "--end") )
		{
			if( ++i >= argc )
				die(usage);
			else{
				tmp = atoi(argv[i]);
				if(tmp < 0)
					die("Versions cannot be negative\n");
				end = (uint32_t)tmp;
				if(end < start)
					die("END must be greater or equal to START\n");
			}
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
	seabrew_bswabe_upd_t* extracted;
	seabrew_bswabe_pub_t* pub;
	
	parse_args(argc, argv);
	
	pub = seabrew_bswabe_pub_unserialize(suck_file(pub_file), 1);
	upd = seabrew_bswabe_upd_unserialize(pub, suck_file(upd_file), 1);
	
	extracted = extract(upd, start, end);
	
	spit_file(out_file, seabrew_bswabe_upd_serialize(extracted), 1);
	
	seabrew_bswabe_upd_free(upd);
	free(upd);
	
	seabrew_bswabe_pub_free(pub);
	free(pub);

	return 0;
}
