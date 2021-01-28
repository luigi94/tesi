#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <pbc.h>
#include <errno.h>
#include <string.h>

#include "bswabe.h"
#include "seabrew.h"
#include "private-bis.h"

GByteArray* seabrew_bswabe_msk_serialize(seabrew_bswabe_msk_t* msk ){

	GByteArray* b;

	b = g_byte_array_new();
	
	b = bswabe_msk_serialize(msk->msk_f);
	serialize_uint32(b, msk->version);	

	return b;
}

GByteArray* seabrew_bswabe_pub_serialize(seabrew_bswabe_pub_t* pub ){

	GByteArray* b;
	
	b = g_byte_array_new();

	b = bswabe_pub_serialize(pub->pub_f);
	serialize_uint32(b, pub->version);
	
	return b;
}

seabrew_bswabe_pub_t* seabrew_bswabe_pub_unserialize( GByteArray* b, int free ){
	seabrew_bswabe_pub_t* pub;
	
	if((pub = (seabrew_bswabe_pub_t*) malloc(sizeof(seabrew_bswabe_pub_t))) == NULL){
		fprintf(stderr, "Error in allocating memory for public key. Error: %s\n", strerror(errno));
		exit(1);
	}
	pub->pub_f = bswabe_pub_unserialize(b, 0);
	pub->version = unserialize_uint32(b, (int[]){b->len - 4});
	
	if( free )
		g_byte_array_free(b, 1);

	return pub;
}

seabrew_bswabe_msk_t* seabrew_bswabe_msk_unserialize(seabrew_bswabe_pub_t* pub, GByteArray* b, int free ){
	seabrew_bswabe_msk_t* msk;

	if((msk = (seabrew_bswabe_msk_t*) malloc(sizeof(seabrew_bswabe_msk_t))) == NULL){
		fprintf(stderr, "Error in allocating memory for master key. Error: %s\n", strerror(errno));
		exit(1);
	}

	msk->msk_f = bswabe_msk_unserialize(pub->pub_f, b, 0);
	msk->version = unserialize_uint32(b, (int[]){b->len - 4});

	if( free )
		g_byte_array_free(b, 1);

	return msk;
}

GByteArray* seabrew_bswabe_prv_serialize( seabrew_bswabe_prv_t* prv ){
	GByteArray* b;
	
	b = g_byte_array_new();
	b = bswabe_prv_serialize(prv->prv_f);
	serialize_uint32(b, prv->version);

	return b;
}

seabrew_bswabe_prv_t* seabrew_bswabe_prv_unserialize(seabrew_bswabe_pub_t* pub, GByteArray* b, int free ){
	seabrew_bswabe_prv_t* prv;

	if((prv = (seabrew_bswabe_prv_t*) malloc(sizeof(seabrew_bswabe_prv_t))) == NULL){
		fprintf(stderr, "Error in allocating memory for private key. Error: %s\n", strerror(errno));
		exit(1);
	}
	prv->prv_f = bswabe_prv_unserialize(pub->pub_f, b, 0);
	prv->version = unserialize_uint32(b, (int[]){b->len - 4});
	
	if( free )
		g_byte_array_free(b, 1);

	return prv;
}

GByteArray* seabrew_bswabe_cph_serialize(seabrew_bswabe_cph_t* cph ){
	GByteArray* b;

	b = g_byte_array_new();
	b = bswabe_cph_serialize(cph->cph_f);
	
	serialize_uint32(b, cph->version);

	return b;
}

seabrew_bswabe_cph_t* seabrew_bswabe_cph_unserialize(seabrew_bswabe_pub_t* pub, GByteArray* b, int free ){
	seabrew_bswabe_cph_t* cph;

	if((cph = (seabrew_bswabe_cph_t*) malloc(sizeof(seabrew_bswabe_cph_t))) == NULL){
		fprintf(stderr, "Error in allocating memory for ciphertext. Error: %s\n", strerror(errno));
		exit(1);
	}
	cph->cph_f = bswabe_cph_unserialize(pub->pub_f, b, 0);
	cph->version = unserialize_uint32(b, (int[]){b->len - 4});
	
	if( free )
		g_byte_array_free(b, 1);

	return cph;
}

GByteArray* seabrew_bswabe_upd_serialize(seabrew_bswabe_upd_t* upd ){
	if(upd == NULL){
		fprintf(stderr, "Update Key is not initialized yet, exit\n");
		return NULL;
	}
	seabrew_bswabe_upd_t* current_node = upd;
	GByteArray* b;
	b = g_byte_array_new();
	while(current_node != NULL){
		serialize_element(b, current_node->u_cp);
		serialize_element(b, current_node->u_pk);
		serialize_uint32(b, current_node->v_uk);
		current_node = current_node -> next;
	}
	return b;
}

seabrew_bswabe_upd_t* seabrew_bswabe_upd_unserialize(seabrew_bswabe_pub_t* pub, GByteArray* b, int free ){

	seabrew_bswabe_upd_t* upd = NULL;
	seabrew_bswabe_upd_t* current = NULL;
	seabrew_bswabe_upd_t* tmp = NULL;

	guint remaining = b->len/(guint)160;
	int offset = 0;

	while(TRUE) {
			if((tmp = (seabrew_bswabe_upd_t*) malloc(sizeof(seabrew_bswabe_upd_t))) == NULL){
				fprintf(stderr, "Error in allocating memory for update key. Error: %s\n", strerror(errno));
				exit(1);
			}
			
			element_init_Zr(tmp->u_cp, &(*pub->pub_f->p));
			element_init_G1(tmp->u_pk, &(*pub->pub_f->p));
			unserialize_element(b, &offset, tmp->u_cp);
			unserialize_element(b, &offset, tmp->u_pk);
			tmp->v_uk = unserialize_uint32(b, &offset);
			
		  if (current == NULL){
		      current = tmp;
		      current->next = NULL;
		      upd = current;
		  } else{
		      current->next = tmp;
		      current = tmp;
		  }
		  tmp->next = NULL;
			remaining--;
			if(remaining == 0)
				break;
	}
	if( free )
		g_byte_array_free(b, 1);

	return upd;
}

GByteArray* seabrew_bswabe_u_x_serialize(seabrew_bswabe_u_x_t* u_x ){
	GByteArray* b;
	b = g_byte_array_new();
	
	serialize_uint32(b, u_x->version);
	serialize_element(b, u_x->u_x);
	
	return b;
}

seabrew_bswabe_u_x_t* seabrew_bswabe_u_x_unserialize(seabrew_bswabe_pub_t* pub, GByteArray* b, int group, int free ){
	seabrew_bswabe_u_x_t* u_x;
	int offset = 0;
	
	if((u_x = (seabrew_bswabe_u_x_t*)malloc(sizeof(seabrew_bswabe_u_x_t))) == NULL){
		fprintf(stderr, "Error in allocating memory. Error: %s\n", strerror(errno));
		exit(1);
	}
	u_x->version = unserialize_uint32(b, &offset);
	if(group == 0){
		element_init_Zr(u_x->u_x, pub->pub_f->p);
	}else if(group == 1){
		element_init_G1(u_x->u_x, pub->pub_f->p);
	} else{
		fprintf(stderr, "Not recognized group for unserialization\n");
		exit(1);
	}
	unserialize_element(b, &offset, u_x->u_x);
	
	if( free )
		g_byte_array_free(b, 1);

	return u_x;
}

void seabrew_bswabe_pub_free(seabrew_bswabe_pub_t* pub){
	bswabe_pub_free(pub->pub_f);
	pub->version = 0U;
}

void seabrew_bswabe_msk_free(seabrew_bswabe_msk_t* msk){
	bswabe_msk_free(msk->msk_f);
	msk->version = 0U;
}

void seabrew_bswabe_prv_free(seabrew_bswabe_prv_t* prv){
	bswabe_prv_free(prv->prv_f);
	prv->version = 0U;
}

void seabrew_bswabe_cph_free(seabrew_bswabe_cph_t* cph){
	bswabe_cph_free(cph->cph_f);
	cph->version = 0U;
}

void seabrew_bswabe_upd_free(seabrew_bswabe_upd_t* head) {
	if(head == NULL){
		fprintf(stderr, "UPD not initilized yet\n");
		return;
	}
	while ( head != NULL) {
		element_clear(head->u_cp);
		element_clear(head->u_pk);
		head = head->next;
  }
  free(head);
}
void seabrew_bswabe_u_x_free(seabrew_bswabe_u_x_t* u_x){
	element_clear(u_x->u_x);
	u_x->version = 0U;
}
