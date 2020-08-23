#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>

#include "bswabe.h"
#include "private.h"
#include "common.h"

char* usage =
"Usage: cpabe-updatepk [OPTION ...] PUB_KEY UPD_KEY\n"
"\n"
"Update the public key PUB_KEY using the update key UPD_KEY up\n"
"to UPD_KEY's version.\n"
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
	unsigned char* buf;
	long upds;
	FILE* f_upd;
	FILE* f_pub;
	
	parse_args(argc, argv);
	
	if(!check_consistency(upd_file)){
		printf("Error in version (2)\n");
		exit(1);
	}
	
	upds = (long) how_many_upd(upd_file);

	if(((f_upd = fopen(upd_file, "r")) == NULL) || ((f_pub = fopen(pub_file, "r+")) == NULL)){
		printf("Error in opening file (2)\n");
		exit(1);
	}
	if((buf = (unsigned char*) malloc(132 * sizeof(unsigned char))) == NULL){
		printf("Error in malloc() (4)\n");
		exit(1);
	}
	
	fseek(f_upd, (long) ((upds - 1) * 160 + 24), SEEK_SET);
	fread(buf, 1, 132L, f_upd);
	
	fseek(f_pub, 492L, SEEK_SET);
	fwrite(buf, 1, 132L, f_pub);
	
	free(buf);
	
	if((buf = (unsigned char*) malloc(4 * sizeof(unsigned char))) == NULL){
		printf("Error in malloc() (5)\n");
		exit(1);
	}
	
	fseek(f_upd, (long) ((upds - 1) * 160 + 156), SEEK_SET);
	fread(buf, 1, 4L, f_upd);

	fseek(f_pub, 888L, SEEK_SET);
	fwrite(buf, 1, 4L, f_pub);
	
	free(buf);
	fclose(f_upd);
	fclose(f_pub);

	return 0;
}
