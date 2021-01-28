#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <pbc.h>

#include "bswabe.h"
#include "private.h"

#define UPD_LEN 160

void
serialize_uint32( GByteArray* b, uint32_t k )
{
	int i;
	guint8 byte;

	for( i = 3; i >= 0; i-- )
	{
		byte = (k & 0xff<<(i*8))>>(i*8);
		g_byte_array_append(b, &byte, 1);
	}
}

uint32_t
unserialize_uint32( GByteArray* b, int* offset )
{
	int i;
	uint32_t r;

	r = 0;
	for( i = 3; i >= 0; i-- )
		r |= (b->data[(*offset)++])<<(i*8);

	return r;
}

void
serialize_element( GByteArray* b, element_t e )
{
	uint32_t len;
	unsigned char* buf;

	len = element_length_in_bytes(e);
	serialize_uint32(b, len);

	buf = (unsigned char*) malloc(len);
	element_to_bytes(buf, e);
	g_byte_array_append(b, buf, len);
	free(buf);
}

void
unserialize_element( GByteArray* b, int* offset, element_t e )
{
	uint32_t len;
	unsigned char* buf;

	len = unserialize_uint32(b, offset);

	buf = (unsigned char*) malloc(len);
	memcpy(buf, b->data + *offset, len);
	*offset += len;

	element_from_bytes(e, buf);
	free(buf);
}

void
serialize_string( GByteArray* b, char* s )
{
	g_byte_array_append(b, (unsigned char*) s, strlen(s) + 1);
}

char*
unserialize_string( GByteArray* b, int* offset )
{
	GString* s;
	char* r;
	char c;

	s = g_string_sized_new(32);
	while( 1 )
	{
		c = b->data[(*offset)++];
		if( c && c != EOF )
			g_string_append_c(s, c);
		else
			break;
	}

	r = s->str;
	g_string_free(s, 0);

	return r;
}

GByteArray*
bswabe_pub_serialize( bswabe_pub_t* pub )
{
	GByteArray* b;

	b = g_byte_array_new();
	serialize_string(b,  pub->pairing_desc);
	serialize_element(b, pub->g);
	serialize_element(b, pub->h);
	serialize_element(b, pub->gp);
	serialize_element(b, pub->g_hat_alpha);

	serialize_uint32(b, pub->v_ek);	//

	return b;
}

bswabe_pub_t*
bswabe_pub_unserialize( GByteArray* b, int free )
{
	bswabe_pub_t* pub;
	int offset;

	pub = (bswabe_pub_t*) malloc(sizeof(bswabe_pub_t));
	offset = 0;

	pub->pairing_desc = unserialize_string(b, &offset);
	pairing_init_set_buf(pub->p, pub->pairing_desc, strlen(pub->pairing_desc));

	element_init_G1(pub->g,           pub->p);
	element_init_G1(pub->h,           pub->p);
	element_init_G2(pub->gp,          pub->p);
	element_init_GT(pub->g_hat_alpha, pub->p);

	unserialize_element(b, &offset, pub->g);
	unserialize_element(b, &offset, pub->h);
	unserialize_element(b, &offset, pub->gp);
	unserialize_element(b, &offset, pub->g_hat_alpha);

	pub->v_ek = unserialize_uint32(b, &offset);	//

	if( free )
		g_byte_array_free(b, 1);

	return pub;
}

GByteArray*
bswabe_msk_serialize( bswabe_msk_t* msk )
{
	GByteArray* b;
	
	b = g_byte_array_new();
	serialize_element(b, msk->beta);
	serialize_element(b, msk->g_alpha);
	serialize_uint32(b, msk->v_mk);	//

	return b;
}

bswabe_msk_t*
bswabe_msk_unserialize( bswabe_pub_t* pub, GByteArray* b, int free )
{
	bswabe_msk_t* msk;
	int offset;

	msk = (bswabe_msk_t*) malloc(sizeof(bswabe_msk_t));
	offset = 0;

	element_init_Zr(msk->beta, pub->p);
	element_init_G2(msk->g_alpha, pub->p);

	unserialize_element(b, &offset, msk->beta);
	unserialize_element(b, &offset, msk->g_alpha);

	msk->v_mk = unserialize_uint32(b, &offset); //

	if( free )
		g_byte_array_free(b, 1);

	return msk;
}

GByteArray*
bswabe_prv_serialize( bswabe_prv_t* prv )
{
	GByteArray* b;
	int i;

	b = g_byte_array_new();
	serialize_element(b, prv->d);
	serialize_uint32( b, prv->comps->len);

	for( i = 0; i < prv->comps->len; i++ )
	{
		serialize_string( b, g_array_index(prv->comps, bswabe_prv_comp_t, i).attr);
		serialize_element(b, g_array_index(prv->comps, bswabe_prv_comp_t, i).d);
		serialize_element(b, g_array_index(prv->comps, bswabe_prv_comp_t, i).dp);
	}
	serialize_uint32(b, prv->v_dk);	//

	return b;
}
GByteArray*
bswabe_build_partial_updates_and_serialize(bswabe_msk_t* msk, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	GByteArray* b;
	unsigned char* buf;
	b = g_byte_array_new();
	
	serialize_uint32(b, msk->v_mk);
	
	if((buf = (unsigned char*) malloc(128)) == NULL){
		printf("Error in malloc() (22)\n");
		exit(1);
	}
	
	element_to_bytes(buf, pub->h);
	g_byte_array_append(b, buf, 128);
	
	element_to_bytes(buf, prv->d);
	g_byte_array_append(b, buf, 128);
	
	free(buf);
	
	return b;
}

bswabe_prv_t*
bswabe_prv_unserialize( bswabe_pub_t* pub, GByteArray* b, int free )
{
	bswabe_prv_t* prv;
	int i;
	int len;
	int offset;

	prv = (bswabe_prv_t*) malloc(sizeof(bswabe_prv_t));
	offset = 0;

	element_init_G2(prv->d, pub->p);
	unserialize_element(b, &offset, prv->d);

	prv->comps = g_array_new(0, 1, sizeof(bswabe_prv_comp_t));
	len = unserialize_uint32(b, &offset);

	for( i = 0; i < len; i++ )
	{
		bswabe_prv_comp_t c;

		c.attr = unserialize_string(b, &offset);

		element_init_G2(c.d,  pub->p);
		element_init_G2(c.dp, pub->p);

		unserialize_element(b, &offset, c.d);
		unserialize_element(b, &offset, c.dp);

		g_array_append_val(prv->comps, c);
	}

	prv->v_dk = unserialize_uint32(b, &offset);	//

	if( free )
		g_byte_array_free(b, 1);

	return prv;
}

void
serialize_policy( GByteArray* b, bswabe_policy_t* p )
{
	int i;

	serialize_uint32(b, (uint32_t) p->k);

	serialize_uint32(b, (uint32_t) p->children->len);
	if( p->children->len == 0 )
	{
		serialize_string( b, p->attr);
		serialize_element(b, p->c);
		serialize_element(b, p->cp);
	}
	else
		for( i = 0; i < p->children->len; i++ )
			serialize_policy(b, g_ptr_array_index(p->children, i));
}

bswabe_policy_t*
unserialize_policy( bswabe_pub_t* pub, GByteArray* b, int* offset )
{
	int i;
	int n;
	bswabe_policy_t* p;

	p = (bswabe_policy_t*) calloc(1, sizeof(bswabe_policy_t));

	p->k = (int) unserialize_uint32(b, offset);
	p->attr = 0;
	p->children = g_ptr_array_new();

	n = unserialize_uint32(b, offset);
	if( n == 0 )
	{
		p->attr = unserialize_string(b, offset);
		element_init_G1(p->c,  pub->p);
		element_init_G1(p->cp, pub->p);
		unserialize_element(b, offset, p->c);
		unserialize_element(b, offset, p->cp);
	}
	else
		for( i = 0; i < n; i++ )
			g_ptr_array_add(p->children, unserialize_policy(pub, b, offset));

	return p;
}

GByteArray*
bswabe_cph_serialize( bswabe_cph_t* cph )
{
	GByteArray* b;
	
	
	b = g_byte_array_new();
	serialize_element(b, cph->cs);
	serialize_element(b, cph->c);
	serialize_policy( b, cph->p);
	serialize_uint32(b, cph->v_cp);	//

	return b;
}

bswabe_cph_t*
bswabe_cph_unserialize( bswabe_pub_t* pub, GByteArray* b, int free )
{
	bswabe_cph_t* cph;
	int offset;

	cph = (bswabe_cph_t*) malloc(sizeof(bswabe_cph_t));
	offset = 0;

	element_init_GT(cph->cs, pub->p);
	element_init_G1(cph->c,  pub->p);
	unserialize_element(b, &offset, cph->cs);
	unserialize_element(b, &offset, cph->c);
	cph->p = unserialize_policy(pub, b, &offset);

	cph->v_cp = unserialize_uint32(b, &offset);	//

	if( free )
		g_byte_array_free(b, 1);

	return cph;
}

GByteArray*
bswabe_upd_serialize( bswabe_upd_t* upd )
{
	if(upd == NULL){
		printf("Update Key is not initialized yet\n");
		return NULL;
	}
	bswabe_upd_t* current_node = upd;
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

bswabe_upd_t*
bswabe_upd_unserialize( bswabe_pub_t* pub, GByteArray* b, char* upd_file, int free )
{
	int offset = 0;
	uint32_t i;
	uint32_t iter;
	
	FILE* fp = fopen(upd_file, "r"); 
	if (fp == NULL)
	{ 
		printf("Error in opening file (9)\n"); 
		exit(1); 
	} 
	fseek(fp, 0L, SEEK_END); 
	iter = (uint32_t) ftell(fp) / UPD_LEN;
	fclose(fp);
	
	bswabe_upd_t* upd = NULL;
	bswabe_upd_t* current_node = NULL;

	for(i = 0; i < iter; i++){
		bswabe_upd_t*  new_node = (bswabe_upd_t*)malloc(sizeof(bswabe_upd_t));
		if (new_node == NULL){
			printf("Error in malloc() (23)\n");
			exit(1);
		}
		element_init_Zr(new_node->u_cp, pub->p);
		element_init_G1(new_node->u_pk, pub->p);

		unserialize_element(b, &offset, new_node->u_cp);
		unserialize_element(b, &offset,new_node->u_pk);
		new_node->v_uk = unserialize_uint32(b, &offset);

		if (current_node == NULL){
			current_node = new_node;
			current_node->next = NULL;
			upd = current_node;
		} else {
			current_node->next = new_node;
			new_node->next = NULL;
			current_node = new_node;
		}
	}
	if( free )
		g_byte_array_free(b, 1);

	return upd;
}

void
bswabe_pub_free( bswabe_pub_t* pub )
{
	element_clear(pub->g);
	element_clear(pub->h);
	element_clear(pub->gp);
	element_clear(pub->g_hat_alpha);
	pairing_clear(pub->p);
	free(pub->pairing_desc);
	pub->v_ek = 0;
	free(pub);
}

void
bswabe_msk_free( bswabe_msk_t* msk )
{
	element_clear(msk->beta);
	element_clear(msk->g_alpha);
	msk->v_mk = 0;
	free(msk);
}

void
bswabe_prv_free( bswabe_prv_t* prv )
{
	int i;
	
	element_clear(prv->d);

	for( i = 0; i < prv->comps->len; i++ )
	{
		bswabe_prv_comp_t c;

		c = g_array_index(prv->comps, bswabe_prv_comp_t, i);
		free(c.attr);
		element_clear(c.d);
		element_clear(c.dp);
	}

	g_array_free(prv->comps, 1);
	
	prv->v_dk = 0;

	free(prv);
}

void
bswabe_policy_free( bswabe_policy_t* p )
{
	int i;

	if( p->attr )
	{
		free(p->attr);
		element_clear(p->c);
		element_clear(p->cp);
	}

	for( i = 0; i < p->children->len; i++ )
		bswabe_policy_free(g_ptr_array_index(p->children, i));

	g_ptr_array_free(p->children, 1);

	free(p);
}

void
bswabe_cph_free( bswabe_cph_t* cph )
{
	element_clear(cph->cs);
	element_clear(cph->c);
	cph->v_cp = 0;
	bswabe_policy_free(cph->p);
}

void bswabe_upd_free(bswabe_upd_t* upd ){
	while(upd != NULL){
		element_clear(upd->u_cp);
		element_clear(upd->u_pk);
		upd->v_uk = 0;
		upd = upd->next;
	}
}
