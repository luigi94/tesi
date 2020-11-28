#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <glib.h>
#include <pbc.h>

#include "bswabe.h"
#include "seabrew.h"
#include "private-bis.h"

#define UPD_LEN 160

void seabrew_bswabe_setup(seabrew_bswabe_pub_t** pub, seabrew_bswabe_msk_t** msk){

	if((*pub = malloc(sizeof(seabrew_bswabe_pub_t))) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
		exit(1);
	
	}
	if((*msk = malloc(sizeof(seabrew_bswabe_msk_t))) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
		exit(1);
	}
	bswabe_setup(&((*pub)->pub_f), &((*msk)->msk_f));
	(*pub)->version = 0U;
	(*msk)->version = 0U;
}

seabrew_bswabe_prv_t* seabrew_bswabe_keygen(seabrew_bswabe_pub_t* pub, seabrew_bswabe_msk_t* msk, char** attributes, seabrew_bswabe_partial_updates_t** partial_updates){
	
	seabrew_bswabe_prv_t* prv;
	
	if((prv = malloc(sizeof(seabrew_bswabe_prv_t))) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
		exit(1);
	}
	prv->prv_f = bswabe_keygen(pub->pub_f, msk->msk_f, attributes);
	prv->version = msk->version;
	
	if((*partial_updates = (seabrew_bswabe_partial_updates_t*)malloc(sizeof(seabrew_bswabe_partial_updates_t))) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
		exit(1);
	}
	
	// Buildin partial updates
	(*partial_updates)->version = msk->version;
	element_init_G1((*partial_updates)->pub_h, pub->pub_f->p);
	element_set((*partial_updates)->pub_h, pub->pub_f->h);
	element_init_G2((*partial_updates)->prv_d, pub->pub_f->p);
	element_set((*partial_updates)->prv_d, prv->prv_f->d);
	
	return prv;
}

seabrew_bswabe_cph_t* seabrew_bswabe_enc(seabrew_bswabe_pub_t* pub, element_t m, char* policy ){
	
	seabrew_bswabe_cph_t* cph;
	
	if((cph = malloc(sizeof(seabrew_bswabe_cph_t))) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
		exit(1);
	}
	
  if( !(cph->cph_f = bswabe_enc(pub->pub_f, m, policy)) )
		return NULL;
		
	cph->version = pub->version;
	return cph;
}

int seabrew_bswabe_dec(seabrew_bswabe_pub_t* pub, seabrew_bswabe_prv_t* prv, seabrew_bswabe_cph_t* cph, element_t m ){
	
	return bswabe_dec(pub->pub_f, prv->prv_f, cph->cph_f, m);
	
}

int check_consistency(char* upd_file){ // 1 if consistent, 0 otherwise
	FILE* f;
	unsigned char* buf;
	uint32_t current_version;
	uint32_t last_version;
	long pointer;
	long dim;
	int i;
	if((f = fopen(upd_file, "r")) == NULL){
		fprintf(stderr, "Error in opening %s. Error: %s\n", upd_file, strerror(errno));
		exit(1);
	}
	if((buf = (unsigned char*) malloc(sizeof(uint32_t))) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
		exit(1);
	}
	pointer = 156L;
	fseek(f, pointer, SEEK_SET);
	fread(buf, 1, 4L, f);
	last_version = 0;
	for(i = 3; i >= 0; i-- )
		last_version |= (buf[(3 - i)])<<(i*8);
	if(last_version <= 0)
		return 0;
	
	fseek(f, 0L, SEEK_END);
	dim = ftell(f);
	
	pointer += 160L;
	
	while(TRUE){
		if(pointer > dim)
			break;
		fseek(f, pointer, SEEK_SET);
		fread(buf, 1, 4L, f);
		current_version = 0;
		for(i = 3; i >= 0; i-- )
			current_version |= (buf[(3 - i)])<<(i*8);
		if(current_version <= 0 || last_version != current_version - 1U)
			return 0;
		pointer += 160L;
		last_version = current_version;
		
	}
	fclose(f);
	free(buf);
	return 1;
}

uint32_t how_many_upd(char* upd_file){
	uint32_t iter;
	FILE* f;
	
	if( access( upd_file, F_OK ) == -1 )
		return (uint32_t) 0;
		
	if ((f = fopen(upd_file, "r") ) == NULL){ 
		fprintf(stderr, "Error in opening %s. Error: %s\n", upd_file, strerror(errno)); 
		exit(1); 
	} 
	fseek(f, 0L, SEEK_END);

	iter = (uint32_t) ftell(f) / UPD_LEN;
	fclose(f);
	return iter;
}

void seabrew_bswabe_update_mk(seabrew_bswabe_pub_t* pub, char* msk_file, char* upd_file){
	FILE* f;
	unsigned char* buf;
	int i;
	seabrew_bswabe_upd_t* new_node;
	element_t beta;
	element_t old_beta;
	
	if((f = fopen(msk_file, "r+")) == NULL){
		fprintf(stderr, "Error in opening %s. Error: %s\n", msk_file, strerror(errno));
		exit(1);
	}
	// Fetch old beta
	element_init_Zr(old_beta, pub->pub_f->p);
	if((buf = (unsigned char*) malloc(20)) == NULL){
		fprintf(stderr, "Error in allocating memory. Error %s\n", strerror(errno));
		exit(1);
	}
	fseek(f, 4L, SEEK_SET);
	fread(buf, 1, 20L, f);
	element_from_bytes(old_beta, buf);
	
	// Write new beta
	element_init_Zr(beta, pub->pub_f->p);
	element_random(beta);
	element_to_bytes(buf, beta);
	fseek(f, 4L, SEEK_SET);
	fwrite(buf, 1, 20L, f);
	free(buf);
	
	// Increment version
	if((buf = (unsigned char*) malloc(sizeof(uint32_t))) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
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
	if((new_node = (seabrew_bswabe_upd_t*) malloc(sizeof(seabrew_bswabe_upd_t))) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
		exit(1);
	}
	element_init_Zr(new_node->u_cp, pub->pub_f->p);
	element_init_G1(new_node->u_pk, pub->pub_f->p);
	element_div(new_node->u_cp, beta, old_beta);	// new_node->u_cp => beta_vmk / (beta_vmk - 1)
	element_pow_zn(new_node->u_pk, pub->pub_f->g, beta);		// new_node->u_pk => g^beta_vmk
	new_node->v_uk = how_many_upd(upd_file) + 1U;
	new_node->next = NULL;
	if( access( upd_file, F_OK ) != -1 && !check_consistency(upd_file)){
		fprintf(stderr, "Error in version, exit\n");
		exit(1);
	}
	update_file(upd_file, seabrew_bswabe_upd_serialize(new_node), 1 );
	seabrew_bswabe_upd_free(new_node);
	
	element_clear(beta);
	element_clear(old_beta);
}

void seabrew_bswabe_update_cp(seabrew_bswabe_pub_t* pub, char* cph_file, char* upd_file) {
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
	
	if(!check_consistency(upd_file)){
		fprintf(stderr, "Error in version, exit\n");
		exit(1);
	}

	if((f_cph = fopen(cph_file, "r+")) == NULL || (f_upd = fopen(upd_file, "r")) == NULL) {
		fprintf(stderr, "Error in opening %s. Error: %s\n", cph_file, strerror(errno));
		exit(1);
	}

	if((f_upd = fopen(upd_file, "r")) == NULL) {
		fprintf(stderr, "Error in opening %s. Error: %s\n", upd_file, strerror(errno));
		exit(1);
	}
	
	// Fetch decryption key version
	if((buf = (unsigned char*) malloc(sizeof(uint32_t))) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
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
				return;
			break;
		}
		pointer += 160L;
		if(pointer > dim){
			fprintf(stderr, "Error in version, exit\n");
			exit(1);
		}
	}
	free(buf);
	
	// Fetch all u_cp(s)
	element_init_Zr(exp, pub->pub_f->p);
	element_init_Zr(current_exp, pub->pub_f->p);
	if((buf = (unsigned char*) malloc(20)) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
		exit(1);
	}
	element_set1(exp);
	while(TRUE){
		if(pointer > dim){
			free(buf);
			if((buf = (unsigned char*) malloc(sizeof(uint32_t))) == NULL){
				fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
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
	element_init_G1(base, pub->pub_f->p);
	if((buf = (unsigned char*) malloc(128)) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
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
}

void seabrew_bswabe_update_partial_updates(seabrew_bswabe_pub_t* pub, char* updates_file, char* upd_file){
	/* TODO update the error messages */
	element_t exp;
	element_t current_exp;
	element_t base;
	unsigned char* buf;
	uint32_t version;
	uint32_t current_version;
	int i;
	long dim;
	long pointer;
	FILE* f_updates;
	FILE* f_upd;
	
	if(!check_consistency(upd_file)){
		fprintf(stderr, "Error in version in file %s, exit\n", upd_file);
		exit(1);
	}
	
	if((f_upd = fopen(upd_file, "r")) == NULL) {
		fprintf(stderr, "Error in opening %s. Error: %s\n", upd_file, strerror(errno));
		exit(1);
	}
	
	if((f_updates = fopen(updates_file, "r+")) == NULL) {
		fprintf(stderr, "Error in opening %s. Error: %s\n", updates_file, strerror(errno));
		exit(1);
	}
	
	// Fetch decryption key version
	if((buf = (unsigned char*) malloc(sizeof(uint32_t))) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
		exit(1);
	}
	
	fread(buf, 1, 4L, f_updates);
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
				return;
			break;
		}
		pointer += 160L;
		if(pointer > dim){
			fprintf(stderr, "Error in version, exit\n");
			exit(1);
		}
	}
	free(buf);
	
	// Fetch all u_cp(s)
	element_init_Zr(exp, pub->pub_f->p);
	element_init_Zr(current_exp, pub->pub_f->p);
	if((buf = (unsigned char*) malloc(20)) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
		exit(1);
	}
	element_set1(exp);
	while(TRUE){
		if(pointer > dim){
			free(buf);
			if((buf = (unsigned char*) malloc(sizeof(uint32_t))) == NULL){
				fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
				exit(1);
			}
			// Write version
			pointer -= 8L;
			fseek(f_upd, pointer, SEEK_SET);
			fread(buf, 1, 4L, f_upd);
			fseek(f_updates, 0L, SEEK_SET);
			fwrite(buf, 1, 4L, f_updates);
			free(buf);
			
			if((buf = (unsigned char*) malloc(128)) == NULL){
				fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
				exit(1);
			}
			
			// Write new h (u_pk)
			pointer -= 128L;
			fseek(f_upd, pointer, SEEK_SET);
			fread(buf, 1, 128L, f_upd);
			//fseek(f_updates, 4L, SEEK_SET);
			fwrite(buf, 1, 128L, f_updates);	
			
			break;
		}
		fseek(f_upd, pointer, SEEK_SET);
		fread(buf, 1, 20L, f_upd);
		element_from_bytes(current_exp, buf);
		element_mul(exp, exp, current_exp);
		pointer += 160L;
	}
	free(buf);
	
	// Exponentiation and write new D
	element_invert(exp, exp);
	element_init_G2(base, pub->pub_f->p);
	if((buf = (unsigned char*) malloc(128)) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
		exit(1);
	}
	// Write new d
	fread(buf, 1, 128L, f_updates);
	element_from_bytes(base, buf);
	element_pow_zn(base, base, exp);
	element_to_bytes(buf, base);
	fseek(f_updates, 132L, SEEK_SET);
	fwrite(buf, 1, 128L, f_updates);
	
	element_clear(exp);
	element_clear(current_exp);
	element_clear(base);
	fclose(f_upd);
	fclose(f_updates);
}

void seabrew_bswabe_update_pub_and_prv_keys_partial(char* partial_updates_file, char* pub_file, char* prv_file){
	
	unsigned char* buf;
	FILE* f_updates;
	FILE* f_pub;
	FILE* f_prv;
	
	if((f_updates = fopen(partial_updates_file, "r")) == NULL ) {
		fprintf(stderr, "Error in opening %s. Error: %s\n", partial_updates_file, strerror(errno));
		exit(1);
	}
	
	if((f_prv = fopen(prv_file, "r+")) == NULL) {
		fprintf(stderr, "Error in opening %s. Error: %s\n", prv_file, strerror(errno));
		exit(1);
	}
	
	if((f_pub = fopen(pub_file, "r+")) == NULL) {
		fprintf(stderr, "Error in opening %s. Error: %s\n", pub_file, strerror(errno));
		exit(1);
	}
	
	if((buf = (unsigned char*) malloc(sizeof(uint32_t))) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
		exit(1);
	}
	
	fread(buf, 1, 4L, f_updates);
	
	// Update decryption key version
	fseek(f_prv, -4L, SEEK_END);
	fwrite(buf, 1, 4L, f_prv);
	
	//Update public key version
	fseek(f_pub, -4L, SEEK_END);
	fwrite(buf, 1, 4L, f_pub);
	free(buf);
	
	if((buf = (unsigned char*) malloc(128)) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
		exit(1);
	}
	
	// Update h field in public key
	fread(buf, 1, 128L, f_updates);
	fseek(f_pub, 496L, SEEK_SET);
	fwrite(buf, 1, 128L, f_pub);
	
	// Update d field in private key
	fread(buf, 1, 128L, f_updates);
	fseek(f_prv, 4L, SEEK_SET);
	fwrite(buf, 1, 128L, f_prv);
	
	free(buf);
	
	fclose(f_updates);
	fclose(f_prv);
	fclose(f_pub);
}
