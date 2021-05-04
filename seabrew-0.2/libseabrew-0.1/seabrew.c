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

void seabrew_bswabe_setup(seabrew_bswabe_pub_t** pub, seabrew_bswabe_msk_t** msk){

	if((*pub = malloc(sizeof(seabrew_bswabe_pub_t))) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
		exit(1);
	
	}
	if((*msk = malloc(sizeof(seabrew_bswabe_msk_t))) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
		free(*pub);
		exit(1);
	}
	bswabe_setup(&((*pub)->pub_f), &((*msk)->msk_f));
	(*pub)->version = 0U;
	(*msk)->version = 0U;
}

seabrew_bswabe_prv_t* seabrew_bswabe_keygen(seabrew_bswabe_pub_t* pub, seabrew_bswabe_msk_t* msk, char** attributes){
	
	seabrew_bswabe_prv_t* prv;
	
	if((prv = malloc(sizeof(seabrew_bswabe_prv_t))) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
		exit(1);
	}
	prv->prv_f = bswabe_keygen(pub->pub_f, msk->msk_f, attributes);
	prv->version = msk->version;
	
	return prv;
}

seabrew_bswabe_d_t* seabrew_bswabe_extract_d(seabrew_bswabe_pub_t* pub, seabrew_bswabe_prv_t* prv){

	seabrew_bswabe_d_t* d;
	
	if((d = malloc(sizeof(seabrew_bswabe_d_t))) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
		exit(1);
	}
	
	element_init_G2(d->d, pub->pub_f->p);
	element_set(d->d, prv->prv_f->d);
	d->version = prv->version;
	
	return d;
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
	
	if(cph->version < prv->version){
		fprintf(stderr, "Cannot decrypt, obsolete ciphertext version: %u against %u (decryption key version)\n", cph->version, prv->version);
		return 0;
	}
	if(cph->version > prv->version){
		fprintf(stderr, "Cannot decrypt, obsolete decryption key version: %u against %u (ciphertext version)\n", prv->version, cph->version);
		return 0;
	}
	
	return bswabe_dec(pub->pub_f, prv->prv_f, cph->cph_f, m);
	
}

uint32_t check_consistency(seabrew_bswabe_upd_t* upd){
	seabrew_bswabe_upd_t* tmp;
	uint32_t old_version;
	
	if(!upd->v_uk){
		fprintf(stderr, "First version of update key cannot be 0\n");
		return 0UL;
	}
	
	tmp = upd;
	old_version = tmp->v_uk;
	tmp = tmp->next;
	while(tmp){ // At the end of this cycle old_version will be the latest version
		if(old_version != tmp->v_uk - 1U){
			fprintf(stderr, "UPD consistency fail.\n");
			return 0U;
		}
		old_version = tmp->v_uk;
		tmp = tmp->next;
	}
	return old_version;
}

seabrew_bswabe_upd_t* seabrew_bswabe_update_mk(seabrew_bswabe_pub_t* pub, char* msk_file, seabrew_bswabe_upd_t* upd){
	FILE* f;
	unsigned char* buf;
	int i;
	seabrew_bswabe_upd_t* new_node;
	element_t beta;
	element_t old_beta;
	
	if((f = fopen(msk_file, "r+")) == NULL){
		fprintf(stderr, "Error in opening %s. Error: %s\n", msk_file, strerror(errno));
		goto exit_label0;
	}
	// Fetch old beta
	element_init_Zr(old_beta, pub->pub_f->p);
	if((buf = (unsigned char*) malloc(20)) == NULL){
		fprintf(stderr, "Error in allocating memory. Error %s\n", strerror(errno));
		goto exit_label1;
	}
	fseek(f, 4L, SEEK_SET);
	if(fread(buf, 1, 20L, f) != 20L){
		fprintf(stderr, "Error in reading from file. Error: %s\n", strerror(errno));
		goto exit_label2;
	}
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
		goto exit_label1;
	}
	fseek(f, 156L, SEEK_SET);
	if(fread(buf, 1, 4L, f) != 4L){
		fprintf(stderr, "Error in reading from file. Error: %s\n", strerror(errno));
		goto exit_label2;
	}
	for (i = 3; i >= 0; i--)
		if (++buf[i])
			break;
	fseek(f, 156L, SEEK_SET);
	fwrite(buf, 1, 4L, f);
	free(buf);
	fclose(f);

	// Create new UPD
	if((new_node = (seabrew_bswabe_upd_t*) malloc(sizeof(seabrew_bswabe_upd_t))) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
		goto exit_label2;
	}
	
	if(!upd){
		new_node->v_uk = 1U;
	} else{
		new_node->v_uk = check_consistency(upd);
		if(!new_node){
			fprintf(stderr, "Errors in version, exit\n");
			free(new_node);
			exit(1);
		}
		new_node->v_uk += 1U;
	}
	element_init_Zr(new_node->u_cp, pub->pub_f->p);
	element_init_G1(new_node->u_pk, pub->pub_f->p);
	element_div(new_node->u_cp, beta, old_beta);	// new_node->u_cp => beta_vmk / (beta_vmk - 1)
	element_pow_zn(new_node->u_pk, pub->pub_f->g, beta);		// new_node->u_pk => g^beta_vmk
	new_node->next = NULL;
	
	element_clear(beta);
	element_clear(old_beta);
	
	goto success;
	
	exit_label2:
		free(buf);
	
	exit_label1:
		fclose(f);

	exit_label0:
		exit(1);
		
	success:
		return new_node;
}

void seabrew_bswabe_update_pk(char* pub_file, seabrew_bswabe_u_pk_t* u_pk){
	unsigned char* buf;
	uint32_t version;
	int i;
	FILE* f_pub;
	
	if((f_pub = fopen(pub_file, "r+")) == NULL) {
		fprintf(stderr, "Error in opening %s. Error: %s\n", pub_file, strerror(errno));
		exit(1);
	}
	
	// Fetch decryption key version
	if((buf = (unsigned char*) malloc(sizeof(uint32_t))) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
		fclose(f_pub);
		exit(1);
	}
	fseek(f_pub, -4L, SEEK_END);
	
	if(fread(buf, 1, 4L, f_pub) != 4L){
		fprintf(stderr, "Error in reading from file. Error: %s\n", strerror(errno));
		fclose(f_pub);
		free(buf);
		exit(1);
	}
	version = 0;
	for(i = 3; i >= 0; i-- )
		version |= (buf[(3 - i)])<<(i*8);
	
	if(version > u_pk->version){
		fprintf(stderr, "Public key version (%u) cannot be greater than U's version (%u)\n", version, u_pk->version);
		free(buf);
		fclose(f_pub);
		exit(1);
	}
	
	if(version == u_pk->version){
		fprintf(stdout, "Public key version is equal to latest update key's version (%u). There is no need to update %s\n", version, pub_file);
		free(buf);
		fclose(f_pub);
		return;
	}
	
	free(buf);
	if((buf = (unsigned char*) malloc(128UL)) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
		fclose(f_pub);
		exit(1);
	}
	
	element_to_bytes(buf, u_pk->u_pk);
	fseek(f_pub, 496L, SEEK_SET);
	fwrite(buf, 1, 128L, f_pub);
	
	//Write new version
	free(buf);
	if((buf = (unsigned char*) malloc(sizeof(uint32_t))) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
		fclose(f_pub);
		exit(1);
	}
	buf[3] = u_pk->version&0xff;
	buf[2] = (u_pk->version>>8)&0xff;
	buf[1] = (u_pk->version>>16)&0xff;
	buf[0] = (u_pk->version>>24)&0xff;
	fseek(f_pub, -4L, SEEK_END);
	fwrite(buf, 1, 4L, f_pub);
	
	free(buf);
	fclose(f_pub);
}

void seabrew_bswabe_update_d(seabrew_bswabe_pub_t* pub, char* d_file, seabrew_bswabe_upd_t* upd, seabrew_bswabe_d_t* d) {
	element_t base;
	element_t exponent;
	seabrew_bswabe_upd_t* tmp;
	unsigned char* buf;
	uint32_t d_version;
	uint32_t old_version;
	int i;
	FILE* f_d;
	
	if(!(old_version = check_consistency(upd))){
		fprintf(stderr, "Error in version during D update process\n");
		exit(1);
	}
	
	if((f_d = fopen(d_file, "r+")) == NULL) {
		fprintf(stderr, "Error in opening %s. Error: %s\n", d_file, strerror(errno));
		exit(1);
	}
	
	// Fetch D version
	if((buf = (unsigned char*) malloc(sizeof(uint32_t))) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
		fclose(f_d);
		exit(1);
	}
	
	fseek(f_d, -4L, SEEK_END);
	if(fread(buf, 1, 4L, f_d) != 4L){
		fprintf(stderr, "Error in reading from file. Error: %s\n", strerror(errno));
		fclose(f_d);
		free(buf);
		exit(1);
	}
	d_version = 0U;
	for(i = 3; i >= 0; i-- )
		d_version |= (buf[(3 - i)])<<(i*8);
		
	/* Extra consistency check */
	if(d_version == old_version){
		fprintf(stdout, "D version is equal to U's version (%u). There is no need to update %s\n", d_version, d_file);
		free(buf);
		fclose(f_d);
		return;
	}else if(d_version > old_version){
		fprintf(stderr, "D version (%u) cannot be greater than U's version (%u)\n", d_version, upd->v_uk);
		free(buf);
		fclose(f_d);
		exit(1);
	} else if(upd->v_uk != d_version + 1U && upd->v_uk > d_version){
		fprintf(stderr, "There are missing updates: from %u (D version + 1) to %u (oldest upd version - 1)\n", d_version + 1U, upd->v_uk - 1U);
		free(buf);
		fclose(f_d);
		exit(1);
	}
	
	/* Multiplication (Eq. 12) */
	tmp = upd;
	element_init_same_as(exponent, tmp->u_cp);
	while(tmp->v_uk <= d_version){
		tmp = tmp->next;
	}
	element_set(exponent, tmp->u_cp);
	while(TRUE){
		if(tmp->next){
			tmp = tmp->next;
			element_mul(exponent, exponent, tmp->u_cp);
		}else{
			d_version = tmp->v_uk;
			break;
		}
	}
	element_invert(exponent, exponent);
	
	// Exponentiation and write new D
	element_init_G2(base, pub->pub_f->p);
	free(buf);
	if((buf = (unsigned char*) malloc(128UL)) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
		fclose(f_d);
		exit(1);
	}
	fseek(f_d, 4UL, SEEK_SET);
	if(fread(buf, 1, 128L, f_d) != 128L){
		fprintf(stderr, "Error in reading from file. Error: %s\n", strerror(errno));
		fclose(f_d);
		free(buf);
		exit(1);
	}
	element_from_bytes(base, buf);

	element_pow_zn(base, base, exponent);
	element_to_bytes(buf, base);
	fseek(f_d, 4UL, SEEK_SET);
	fwrite(buf, 1, 128L, f_d);
	
	//Write new version
	free(buf);
	if((buf = (unsigned char*) malloc(sizeof(uint32_t))) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
		fclose(f_d);
		exit(1);
	}
	buf[3] = d_version&0xff;
	buf[2] = (d_version>>8)&0xff;
	buf[1] = (d_version>>16)&0xff;
	buf[0] = (d_version>>24)&0xff;
	fseek(f_d, -4L, SEEK_END);
	fwrite(buf, 1, 4L, f_d);
	
	/* Free memory */
	free(buf);
	element_clear(base);
	element_clear(exponent);
	fclose(f_d);
}

void seabrew_bswabe_update_cp(seabrew_bswabe_pub_t* pub, char* cph_file, seabrew_bswabe_upd_t* upd) {
	element_t base;
	element_t exponent;
	seabrew_bswabe_upd_t* tmp;
	unsigned char* buf;
	uint32_t cph_version;
	uint32_t old_version;
	int i;
	long pointer;
	int len;
	FILE* f_cph;
	
	if(!(old_version = check_consistency(upd))){
		fprintf(stderr, "Error in version during D update process\n");
		exit(1);
	}
	
	if((f_cph = fopen(cph_file, "r+")) == NULL) {
		fprintf(stderr, "Error in opening %s. Error: %s\n", cph_file, strerror(errno));
		exit(1);
	}
	
	// Fetch ciphertext key version
	if((buf = (unsigned char*) malloc(sizeof(uint32_t))) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
		fclose(f_cph);
		exit(1);
	}
	
	fseek(f_cph, -4L, SEEK_END);
	if(fread(buf, 1, 4L, f_cph) != 4L){
		fprintf(stderr, "Error in reading from file. Error: %s\n", strerror(errno));
		fclose(f_cph);
		free(buf);
		exit(1);
	}
	cph_version = 0U;
	for(i = 3; i >= 0; i-- )
		cph_version |= (buf[(3 - i)])<<(i*8);
		
	/* Extra consistency check */
	if(cph_version == old_version){
		fprintf(stdout, "Ciphertext version is equal to the latest update key's version (%u). There is no need to update %s\n", cph_version, cph_file);
		free(buf);
		fclose(f_cph);
		return;
	}else if(cph_version > old_version){
		fprintf(stderr, "Ciphertext version (%u) cannot be greater than U's version (%u)\n", cph_version, upd->v_uk);
		free(buf);
		fclose(f_cph);
		exit(1);
	} else if(upd->v_uk != cph_version + 1U && upd->v_uk > cph_version){
		fprintf(stderr, "There are missing updates: from %u (ciphertext version + 1) to %u (oldest upd version - 1)\n", cph_version + 1U, upd->v_uk - 1U);
		free(buf);
		fclose(f_cph);
		exit(1);
	}
	
	/* Multiplication (Eq. 12) */
	tmp = upd;
	element_init_same_as(exponent, tmp->u_cp);
	while(tmp->v_uk <= cph_version){
		tmp = tmp->next;
	}
	element_set(exponent, tmp->u_cp);
	while(TRUE){
		if(tmp->next){
			tmp = tmp->next;
			element_mul(exponent, exponent, tmp->u_cp);
		}else{
			cph_version = tmp->v_uk;
			break;
		}
	}
	
	// Exponentiation and write new C
	element_init_G1(base, pub->pub_f->p);
	free(buf);
	if((buf = (unsigned char*) malloc(128UL)) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
		fclose(f_cph);
		exit(1);
	}
	fseek(f_cph, 4L, SEEK_SET);
	len = 0;
	for( i = 3; i >= 0; i-- )
		len |= fgetc(f_cph)<<(i*8);
	pointer = (long) len + 148L;
	fseek(f_cph, pointer, SEEK_SET);
	if(fread(buf, 1, 128L, f_cph) != 128L){
		fprintf(stderr, "Error in reading from file. Error: %s\n", strerror(errno));
		fclose(f_cph);
		free(buf);
		exit(1);
	}
	element_from_bytes(base, buf);
	element_pow_zn(base, base, exponent);
	element_to_bytes(buf, base);
	fseek(f_cph, pointer, SEEK_SET);
	fwrite(buf, 1, 128L, f_cph);
	
	//Write new version
	free(buf);
	if((buf = (unsigned char*) malloc(sizeof(uint32_t))) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
		fclose(f_cph);
		exit(1);
	}
	buf[3] = cph_version&0xff;
	buf[2] = (cph_version>>8)&0xff;
	buf[1] = (cph_version>>16)&0xff;
	buf[0] = (cph_version>>24)&0xff;
	fseek(f_cph, -4L, SEEK_END);
	fwrite(buf, 1, 4L, f_cph);
	
	/* Free memory */
	free(buf);
	element_clear(base);
	element_clear(exponent);
	fclose(f_cph);
}

void seabrew_bswabe_update_dk(char* prv_file, seabrew_bswabe_d_t* d) {
	unsigned char* buf;
	uint32_t version;
	int i;
	FILE* f_prv;
	
	if((f_prv = fopen(prv_file, "r+")) == NULL) {
		fprintf(stderr, "Error in opening %s. Error: %s\n", prv_file, strerror(errno));
		exit(1);
	}
	
	// Fetch decryption key version
	if((buf = (unsigned char*) malloc(sizeof(uint32_t))) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
		fclose(f_prv);
		exit(1);
	}
	fseek(f_prv, -4L, SEEK_END);
	
	if(fread(buf, 1, 4L, f_prv) != 4L){
		fprintf(stderr, "Error in reading from file. Error: %s\n", strerror(errno));
		fclose(f_prv);
		free(buf);
		exit(1);
	}
	version = 0;
	for(i = 3; i >= 0; i-- )
		version |= (buf[(3 - i)])<<(i*8);
	
	if(version > d->version){
		fprintf(stderr, "Decryption key version (%u) cannot be greater than D's version (%u)\n", version, d->version);
		free(buf);
		fclose(f_prv);
		exit(1);
	}
	
	if(version == d->version){
		fprintf(stdout, "Private key's version is equal to D's version (%u). There is no need to update %s\n", version, prv_file);
		free(buf);
		fclose(f_prv);
		exit(1);
	}
	
	free(buf);
	if((buf = (unsigned char*) malloc(128UL)) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
		fclose(f_prv);
		exit(1);
	}
	element_to_bytes(buf, d->d);
	fseek(f_prv, 4UL, SEEK_SET);
	fwrite(buf, 1, 128UL, f_prv);
	
	//Write new version
	free(buf);
	if((buf = (unsigned char*) malloc(sizeof(uint32_t))) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
		fclose(f_prv);
		exit(1);
	}
	buf[3] = d->version&0xff;
	buf[2] = (d->version>>8)&0xff;
	buf[1] = (d->version>>16)&0xff;
	buf[0] = (d->version>>24)&0xff;
	fseek(f_prv, -4L, SEEK_END);
	fwrite(buf, 1, 4L, f_prv);
	
	free(buf);
	fclose(f_prv);
}

seabrew_bswabe_u_pk_t* extract_u_pk(seabrew_bswabe_upd_t* upd){

	seabrew_bswabe_upd_t* tmp;
	seabrew_bswabe_u_pk_t* res;
	
	if(!check_consistency(upd)){
		fprintf(stderr, "Error in version\n");
		exit(1);
	}
	for(tmp = upd; tmp->next; tmp = tmp->next);
	
	if((res = (seabrew_bswabe_u_pk_t*)malloc(sizeof(seabrew_bswabe_u_pk_t))) == NULL){
		fprintf(stderr, "Error in allocating memeory. Error: %s\n", strerror(errno));
		exit(1);
	}
	element_init_same_as(res->u_pk, tmp->u_pk);
	element_set(res->u_pk, tmp->u_pk);
	res->version = tmp->v_uk;
	return res;
}

seabrew_bswabe_upd_t* extract(seabrew_bswabe_upd_t* upd, uint32_t start, uint32_t end){
	seabrew_bswabe_upd_t* tmp;
	uint32_t old_version;
	
	tmp = upd;
	old_version = tmp->v_uk;
	if(start > end && start != 0 && end != 0){
		fprintf(stderr, "Error in versions interval\n");
		exit(1);
	}
	if(start < old_version && start != 0){
		fprintf(stderr, "Error in versions interval\n");
		exit(1);
	}
	if(tmp->next){
		tmp = tmp->next;
		while(tmp && tmp->next){
			if(old_version != tmp->v_uk - 1U){
				fprintf(stderr, "Update key inconsistent\n");
				exit(1);
			}
			old_version = tmp->v_uk;
			tmp = tmp->next;
		}
		if(old_version != tmp->v_uk - 1U){
			fprintf(stderr, "Update key inconsistent\n");
			exit(1);
		}
		if(start > tmp->v_uk || end > tmp->v_uk ){
			fprintf(stderr, "Error in versions interval\n");
			exit(1);
		}
	}
	if(start == 0 && end == 0)
		return tmp;
	
	while(upd->v_uk < start){
		upd = upd->next;
	}
	tmp = upd;
	if(end != 0){
		while(tmp->v_uk < end) {
			tmp = tmp->next;
		}
	}else{
		while(tmp->next != NULL) {
			tmp = tmp->next;
		}
	}
	tmp->next = NULL;
	return upd;
}

void print_seabrew_msk_t(seabrew_bswabe_msk_t* msk){
	fprintf(stdout, "Printing Master Key (version %u)\n", msk->version);
	element_printf("beta: %B\n", msk->msk_f->beta);
	element_printf("g_alpha: %B\n", msk->msk_f->g_alpha);
	fprintf(stdout, "\n");
}

void print_seabrew_upd_t(seabrew_bswabe_upd_t* head) {
	if(head == NULL){
		fprintf(stderr, "UPD not initilized yet\n");
		return;
	}
	seabrew_bswabe_upd_t *current_node = head;
	fprintf(stdout, "Printing UPD\n");
	while ( current_node != NULL) {
		fprintf(stdout, "Node at version %d:\n", current_node->v_uk);
		element_printf("u_cp: %B\n", current_node->u_cp);
		element_printf("u_pk: %B\n", current_node->u_pk);
		current_node = current_node->next;
  }
  fprintf(stdout, "\n");
}

void print_seabrew_pub_t(seabrew_bswabe_pub_t* pub){
	fprintf(stdout, "Printing Public Key (version %u)\n", pub->version);
	element_printf("pub->h: %B\n", pub->pub_f->h);
	element_printf("pub->g: %B\n", pub->pub_f->g);
	element_printf("pub->g_hat_alpha: %B\n", pub->pub_f->g_hat_alpha);
	element_printf("pub->gp: %B\n", pub->pub_f->gp);
	fprintf(stdout, "\n");
}

void print_seabrew_prv_t(seabrew_bswabe_prv_t* prv){
	fprintf(stdout, "Printing Private Key (Decryption key) (version %u)\n", prv->version);
	element_printf("d: %B\n", prv->prv_f->d);
	fprintf(stdout, "\n");
}

void print_seabrew_cph_t(seabrew_bswabe_cph_t* cph){
	fprintf(stdout, "Printing Ciphertext (version %u)\n", cph->version);
	element_printf("c: %B\n", cph->cph_f->c);
	element_printf("cs: %B\n", cph->cph_f->cs);
	fprintf(stdout, "\n");
}
