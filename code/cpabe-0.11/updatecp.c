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
"Usage: cpabe-updatecp [OPTION ...] CPH UPDATE_KEY PUB_KEY\n"
"\n"
"Blindly update the PRV_KEY using the update key UPDATE_KEY and public key PUB_KEY\n"
"The new ciphertext is updated up to the version \n"
"of UPDATE_KEY.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
"";

char*  cph_file = 0;
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
		else if( !cph_file )
		{
			cph_file = argv[i];
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
	if( !pub_file || !upd_file || !cph_file )
		die(usage);
}

int
main( int argc, char** argv )
{
	bswabe_pub_t* pub;	
	bswabe_cph_t* cph;
	int file_len;
	GByteArray* aes_buf;
	GByteArray* cph_buf;

	parse_args(argc, argv);

	pub = bswabe_pub_unserialize(suck_file(pub_file), 1);

	read_cpabe_file(cph_file, &cph_buf, &file_len, &aes_buf);
	cph = bswabe_cph_unserialize(pub, cph_buf, 0);
	
	unlink(cph_file);
	
	bswabe_update_cp(cph, bswabe_upd_unserialize(pub, suck_file(upd_file), 1), pub);
	
	cph_buf = bswabe_cph_serialize(cph);
	bswabe_cph_free(cph);

	write_cpabe_file(cph_file, cph_buf, file_len, aes_buf);
	
	g_byte_array_free(cph_buf, 1);
	g_byte_array_free(aes_buf, 1);
	file_len = -1;

	return 0;
}
