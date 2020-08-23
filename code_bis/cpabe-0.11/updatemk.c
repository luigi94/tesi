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
	FILE* f;
	unsigned char* buf;
	int i;
	bswabe_pub_t* pub;
	bswabe_upd_t* new_node;
	element_t beta;
	element_t old_beta;
	
	parse_args(argc, argv);
	pub = bswabe_pub_unserialize(suck_file(pub_file), 1);
	
	if((f = fopen(msk_file, "r+")) == NULL){
		printf("Error in opening file (1)\n");
		exit(1);
	}
	
	// Fetch old beta
	element_init_Zr(old_beta, pub->p);
	if((buf = (unsigned char*) malloc(20)) == NULL){
		printf("Error in malloc() (1)\n");
		exit(1);
	}
	fseek(f, 4L, SEEK_SET);
	fread(buf, 1, 20L, f);
	element_from_bytes(old_beta, buf);
	
	// Write new beta
	element_init_Zr(beta, pub->p);
	element_random(beta);
	element_to_bytes(buf, beta);
	fseek(f, 4L, SEEK_SET);
	fwrite(buf, 1, 20L, f);
	free(buf);
	
	// Increment version
	if((buf = (unsigned char*) malloc(sizeof(uint32_t))) == NULL){
		printf("Error in malloc() (2)\n");
		exit(1);
	}
	fseek(f, 156L, SEEK_SET);
	fread(buf, 1, 4L, f);
	for (i = 3; i >= 0; i--)
		if (++buf[i])
			break;
	fseek(f, 156L, SEEK_SET);
	fwrite(buf, 1, 4L, f);
	free(buf);
	fclose(f);
	
	// Create new UPD and add to upd_file
	if((new_node = (bswabe_upd_t*) malloc(sizeof(bswabe_upd_t))) == NULL){
		printf("Error in malloc() (3)\n");
		exit(1);
	}
	element_init_Zr(new_node->u_cp, pub->p);
	element_init_G1(new_node->u_pk, pub->p);
	element_div(new_node->u_cp, beta, old_beta);	// new_node->u_cp => beta_vmk / (beta_vmk - 1)
	element_pow_zn(new_node->u_pk, pub->g, beta);		// new_node->u_pk => g^beta_vmk
	new_node->v_uk = how_many_upd(upd_file) + (uint32_t) 1;
	new_node->next = NULL;
	if( access( upd_file, F_OK ) != -1 && !check_consistency(upd_file)){
		printf("Error in version (1)\n");
		exit(1);
	}
	update_file(upd_file, bswabe_upd_serialize(new_node), 1 );
	bswabe_upd_free(new_node);
	
	element_clear(beta);
	element_clear(old_beta);
	
	return 0;
}
