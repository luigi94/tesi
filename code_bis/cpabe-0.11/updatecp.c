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
"Usage: cpabe-updatecp [OPTION ...] CPH UPD_KEY PUB_KEY\n"
"\n"
"Blindly update the cipher-text CPH using the update key UPD_KEY\n"
"and public key PUB_KEY parameters.\n"
"The new ciphertext is updated up to UPD_KEY's version. \n"
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
	element_t exp;
	element_t current_exp;
	element_t base;
	unsigned char* buf;
	uint32_t version;
	uint32_t current_version;
	int i;
	long dim;
	long pointer;
	int len;
	FILE* f_cph;
	FILE* f_upd;
	int file_len;
	GByteArray* aes_buf;
	GByteArray* cph_buf;
	bswabe_cph_t* cph;
	
	parse_args(argc, argv);
	
	if(!check_consistency(upd_file)){
		printf("Error in version (4)\n");
		exit(1);
	}
	
	pub = bswabe_pub_unserialize(suck_file(pub_file), 1);
	
	read_cpabe_file(cph_file, &cph_buf, &file_len, &aes_buf);
	cph = bswabe_cph_unserialize(pub, cph_buf, 1);

	if((f_cph = fopen(cph_file, "r+")) == NULL || (f_upd = fopen(upd_file, "r")) == NULL) {
		printf("Error in opening file (4)\n");
		exit(1);
	}
	
	// Fetch decryption key version
	if((buf = (unsigned char*) malloc(sizeof(uint32_t))) == NULL){
		printf("Error in malloc() (10)\n");
		exit(1);
	}
	fseek(f_cph, -4L, SEEK_END);
	
	fread(buf, 1, 4L, f_cph);
	version = 0;
	for(i = 3; i >= 0; i-- )
		version |= (buf[(3 - i)])<<(i*8);
	// Find the upd such its version is v_dk+1
	fseek(f_upd, 0L, SEEK_END);
	dim = ftell(f_upd);
	pointer = 156L;
	while(TRUE){
		fseek(f_upd, pointer, SEEK_SET);
		fread(buf, 1, 4L, f_upd);
		current_version = 0;
		for(i = 3; i >= 0; i-- )
			current_version |= (buf[(3 - i)])<<(i*8);
		
		if(current_version > version){
			pointer -= 152L;
			break;
		}
		if(current_version == version){
			pointer += 8L;
			if(pointer > dim)
				return 0;
			break;
		}
		pointer += 160L;
		if(pointer > dim){
			printf("Error in version (5)\n");
			exit(1);
		}
	}
	free(buf);
	
	// Fetch all u_cp(s)
	element_init_Zr(exp, pub->p);
	element_init_Zr(current_exp, pub->p);
	if((buf = (unsigned char*) malloc(20)) == NULL){
		printf("Error in malloc() (11)\n");
		exit(1);
	}
	element_set1(exp);
	while(TRUE){
		if(pointer > dim){
			free(buf);
			if((buf = (unsigned char*) malloc(sizeof(uint32_t))) == NULL){
				printf("Error in malloc() (12)\n");
				exit(1);
			}
			pointer -= 8L;
			fseek(f_upd, pointer, SEEK_SET);
			fread(buf, 1, 4L, f_upd);
			fseek(f_cph, -4L, SEEK_END);
			fwrite(buf, 1, 4L, f_cph);
			break;
		}
		fseek(f_upd, pointer, SEEK_SET);
		fread(buf, 1, 20L, f_upd);
		element_from_bytes(current_exp, buf);
		element_mul(exp, exp, current_exp);
		pointer += 160L;
	}
	free(buf);
	
	// Exponentiation and write new C
	element_init_G1(base, pub->p);
	if((buf = (unsigned char*) malloc(128)) == NULL){
		printf("Error in malloc() (13)\n");
		exit(1);
	}
	fseek(f_cph, 4L, SEEK_SET);
	len = 0;
	for( i = 3; i >= 0; i-- )
		len |= fgetc(f_cph)<<(i*8);
	pointer = (long) len + 148L;
	fseek(f_cph, pointer, SEEK_SET);
	fread(buf, 1, 128L, f_cph);
	element_from_bytes(base, buf);
	element_pow_zn(base, base, exp);
	element_to_bytes(buf, base);
	fseek(f_cph, pointer, SEEK_SET);
	fwrite(buf, 1, 128L, f_cph);
	free(buf);
	
	element_clear(exp);
	element_clear(current_exp);
	element_clear(base);
	fclose(f_upd);
	fclose(f_cph);
	
	return 0;
}
