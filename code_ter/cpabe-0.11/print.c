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
"Usage: cpabe-setup TYPE KEY PUB\n"
"\n"
"Print the KEY of type TYPE\n"
"";

int
main( int argc, char** argv )
{
		if(!strcmp(argv[1], "msk"))
		{
			bswabe_msk_t* msk;
			bswabe_pub_t* pub;
			pub = bswabe_pub_unserialize(suck_file(argv[3]), 1);
			msk = bswabe_msk_unserialize(pub, suck_file(argv[2]), 1);
			print_msk_t(msk);
		}
		else if(!strcmp(argv[1], "pub"))
		{
			bswabe_pub_t* pub;
			pub = bswabe_pub_unserialize(suck_file(argv[2]), 1);
			print_pub_t(pub);
		}
		else if( !strcmp(argv[1], "prv"))
		{
			bswabe_prv_t* prv;
			bswabe_pub_t* pub;
			pub = bswabe_pub_unserialize(suck_file(argv[3]), 1);
			prv = bswabe_prv_unserialize(pub, suck_file(argv[2]), 1);
			print_prv_t(prv);
		}
		else if( !strcmp(argv[1], "upd"))
		{
			bswabe_pub_t* pub;
			bswabe_upd_t* upd;
			pub = bswabe_pub_unserialize(suck_file(argv[3]), 1);
			upd = bswabe_upd_unserialize(pub, suck_file(argv[2]), argv[2], 1);
			print_upd_t(upd);
		}
		else if( !strcmp(argv[1], "cph") )
		{
			bswabe_cph_t* cph;
			bswabe_pub_t* pub;
			int file_len;
			GByteArray* aes_buf;
			GByteArray* cph_buf;
			pub = bswabe_pub_unserialize(suck_file(argv[3]), 1);
			read_cpabe_file(argv[2], &cph_buf, &file_len, &aes_buf);
			cph = bswabe_cph_unserialize(pub, suck_file(argv[2]), 1);
			print_cph_t(cph);
		}
		else if( !strcmp(argv[1], "partial") )
		{
			bswabe_pub_t* pub;
			unsigned char* buf;
			FILE* f;
			element_t d;
			element_t u_pk;
			uint32_t v;
			int i;
			
			if((f = fopen(argv[2], "r+")) == NULL) {
				printf("Error in opening file (3)\n");
				exit(1);
			}
			
			if((buf = (unsigned char*) malloc(sizeof(uint32_t))) == NULL){
				printf("Error in malloc() (9)\n");
				exit(1);
			}
			fread(buf, 1, 4L, f);
			v = 0;
			for(i = 3; i >= 0; i-- )
				v |= (buf[(3 - i)])<<(i*8);

			printf("v: %u\n", v);
			free(buf);
			
			pub = bswabe_pub_unserialize(suck_file(argv[3]), 1);
			if((buf = (unsigned char*) malloc(128)) == NULL){
				printf("Error in malloc() (9)\n");
				exit(1);
			}
			fread(buf, 1, 128L, f);
			element_init_G1(u_pk, pub->p);
			element_from_bytes(u_pk, buf);
			element_printf("U_pk: %B\n", u_pk);
			
			fread(buf, 1, 128L, f);
			element_init_G2(d, pub->p);
			element_from_bytes(d, buf);
			element_printf("D: %B\n", d);
		
			free(buf);
			
			element_clear(d);
			element_clear(u_pk);
			v = 0;
			fclose(f);
		}
		else
			die(usage);
	return 0;
}
