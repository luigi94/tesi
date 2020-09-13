#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifndef BSWABE_DEBUG
#define NDEBUG
#endif
#include <assert.h>

#include <openssl/sha.h>
#include <glib.h>
#include <pbc.h>
#include <errno.h>

#include "bswabe.h"
#include "common.h"
#include "private.h"

#define TYPE_A_PARAMS \
"type a\n" \
"q 87807107996633125224377819847540498158068831994142082" \
"1102865339926647563088022295707862517942266222142315585" \
"8769582317459277713367317481324925129998224791\n" \
"h 12016012264891146079388821366740534204802954401251311" \
"822919615131047207289359704531102844802183906537786776\n" \
"r 730750818665451621361119245571504901405976559617\n" \
"exp2 159\n" \
"exp1 107\n" \
"sign1 1\n" \
"sign0 1\n"

#define UPD_LEN 160

char last_error[256];

char*
bswabe_error()
{
	return last_error;
}

void
raise_error(char* fmt, ...)
{
	va_list args;

#ifdef BSWABE_DEBUG
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	exit(1);
#else
	va_start(args, fmt);
	vsnprintf(last_error, 256, fmt, args);
	va_end(args);
#endif
}

void
element_from_string( element_t h, char* s )
{
	unsigned char* r;

	r = malloc(SHA_DIGEST_LENGTH);
	SHA1((unsigned char*) s, strlen(s), r);
	element_from_hash(h, r, SHA_DIGEST_LENGTH);

	free(r);
}

uint32_t get_cph_version(char* cph_file){
	uint32_t version;
	FILE* f;
	int i;
	unsigned char* buf;
	
	if((f = fopen(cph_file, "r")) == NULL) {
		printf("Error in opening file (6**1)\n");
		exit(1);
	}
	if((buf = (unsigned char*) malloc(sizeof(uint32_t))) == NULL){
		printf("Error in malloc() (20**)\n");
		exit(1);
	}
	fseek(f, -4L, SEEK_END);
	fread(buf, 1, 4L, f);
	version = 0;
	for(i = 3; i >= 0; i-- )
		version |= (buf[(3 - i)])<<(i*8);
	free(buf);
	fclose(f);
	return version;
}

uint32_t get_msk_version(char* msk_file){
	uint32_t version;
	FILE* f;
	int i;
	unsigned char* buf;
	
	if((f = fopen(msk_file, "r")) == NULL) {
		fprintf(stderr, "Error in opening file (1**). Error: %s\n", strerror(errno));
		exit(1);
	}
	if((buf = (unsigned char*) malloc(sizeof(uint32_t))) == NULL){
		printf("Error in malloc() (20**)\n");
		exit(1);
	}
	fseek(f, -4L, SEEK_END);
	fread(buf, 1, 4L, f);
	version = 0;
	for(i = 3; i >= 0; i-- )
		version |= (buf[(3 - i)])<<(i*8);
	free(buf);
	fclose(f);
	return version;
}

uint32_t get_partial_updates_version(char* partial_updates_file){
	uint32_t version;
	FILE* f;
	int i;
	unsigned char* buf;
	
	if((f = fopen(partial_updates_file, "r")) == NULL) {
		fprintf(stderr, "Error in opening file (2**). Error: %s\n", strerror(errno));
		exit(1);
	}
	if((buf = (unsigned char*) malloc(sizeof(uint32_t))) == NULL){
		fprintf(stderr, "Error in malloc(). Error: %s\n", strerror(errno));
		exit(1);
	}
	fread(buf, 1, 4L, f);
	version = 0;
	for(i = 3; i >= 0; i-- )
		version |= (buf[(3 - i)])<<(i*8);
	free(buf);
	fclose(f);
	return version;
}

void
bswabe_setup( char* pub_file, char* msk_file )
{
	bswabe_msk_t* msk;
	bswabe_pub_t* pub;
	element_t alpha;

	/* initialize */
 
	pub = malloc(sizeof(bswabe_pub_t));
	msk = malloc(sizeof(bswabe_msk_t));

	pub->pairing_desc = strdup(TYPE_A_PARAMS);
	pairing_init_set_buf(pub->p, pub->pairing_desc, strlen(pub->pairing_desc));

	element_init_G1(pub->g,           pub->p);
	element_init_G1(pub->h,           pub->p);
	element_init_G2(pub->gp,          pub->p);
	element_init_GT(pub->g_hat_alpha, pub->p);
	element_init_Zr(alpha,               pub->p);
	element_init_Zr(msk->beta,        pub->p);
	element_init_G2(msk->g_alpha,     pub->p);

	/* compute */

 	element_random(alpha);
 	element_random(msk->beta);
	element_random(pub->g);
	element_random(pub->gp);

	element_pow_zn(msk->g_alpha, pub->gp, alpha);
	element_pow_zn(pub->h, pub->g, msk->beta);
  pairing_apply(pub->g_hat_alpha, pub->g, msk->g_alpha, pub->p);
  
  /* version */
  pub->v_ek = 0;
  msk->v_mk = 0;
  
  element_clear(alpha);
  
	spit_file(pub_file, bswabe_pub_serialize(pub), 1);
	spit_file(msk_file, bswabe_msk_serialize(msk), 1);
}

void bswabe_keygen( bswabe_pub_t* pub, char* msk_file, char* out_file, char* partial_updates_file, char** attributes )
{
	bswabe_msk_t* msk;
	bswabe_prv_t* prv;
	element_t g_r;
	element_t r;
	element_t beta_inv;

	/* initialize */
	
	msk = bswabe_msk_unserialize(pub, suck_file(msk_file), 1);

	prv = malloc(sizeof(bswabe_prv_t));

	element_init_G2(prv->d, pub->p);
	element_init_G2(g_r, pub->p);
	element_init_Zr(r, pub->p);
	element_init_Zr(beta_inv, pub->p);

	prv->comps = g_array_new(0, 1, sizeof(bswabe_prv_comp_t));

	/* compute */
 	element_random(r);
	element_pow_zn(g_r, pub->gp, r);

	element_mul(prv->d, msk->g_alpha, g_r);
	element_invert(beta_inv, msk->beta);
	element_pow_zn(prv->d, prv->d, beta_inv);

	while( *attributes )
	{
		bswabe_prv_comp_t c;
		element_t h_rp;
		element_t rp;

		c.attr = *(attributes++);

		element_init_G2(c.d,  pub->p);
		element_init_G1(c.dp, pub->p);
		element_init_G2(h_rp, pub->p);
		element_init_Zr(rp,   pub->p);
		
 		element_from_string(h_rp, c.attr);
 		element_random(rp);

		element_pow_zn(h_rp, h_rp, rp);

		element_mul(c.d, g_r, h_rp);
		element_pow_zn(c.dp, pub->g, rp);

		element_clear(h_rp);
		element_clear(rp);

		g_array_append_val(prv->comps, c);
	}
	
	/* version */
	prv->v_dk = msk->v_mk;
	
	element_clear(g_r);
	element_clear(r);
	element_clear(beta_inv);
	
	spit_file(out_file, bswabe_prv_serialize(prv), 1);
	spit_file(partial_updates_file, bswabe_build_partial_updates_and_serialize(msk, prv, pub), 1);
}

bswabe_policy_t*
base_node( int k, char* s )
{
	bswabe_policy_t* p;

	p = (bswabe_policy_t*) malloc(sizeof(bswabe_policy_t));
	p->k = k;
	p->attr = s ? strdup(s) : 0;
	p->children = g_ptr_array_new();
	p->q = 0;

	return p;
}

/*
	TODO convert this to use a GScanner and handle quotes and / or
	escapes to allow attributes with whitespace or = signs in them
*/

bswabe_policy_t*
parse_policy_postfix( char* s )
{
	char** toks;
	char** cur_toks;
	char*  tok;
	GPtrArray* stack; /* pointers to bswabe_policy_t's */
	bswabe_policy_t* root;

	toks     = g_strsplit(s, " ", 0);
	cur_toks = toks;
	stack    = g_ptr_array_new();

	while( *cur_toks )
	{
		int i, k, n;

		tok = *(cur_toks++);

		if( !*tok )
			continue;

		if( sscanf(tok, "%dof%d", &k, &n) != 2 )
			/* push leaf token */
			g_ptr_array_add(stack, base_node(1, tok));
		else
		{
			bswabe_policy_t* node;

			/* parse "kofn" operator */

			if( k < 1 )
			{
				raise_error("error parsing \"%s\": trivially satisfied operator \"%s\"\n", s, tok);
				return 0;
			}
			else if( k > n )
			{
				raise_error("error parsing \"%s\": unsatisfiable operator \"%s\"\n", s, tok);
				return 0;
			}
			else if( n == 1 )
			{
				raise_error("error parsing \"%s\": identity operator \"%s\"\n", s, tok);
				return 0;
			}
			else if( n > stack->len )
			{
				raise_error("error parsing \"%s\": stack underflow at \"%s\"\n", s, tok);
				return 0;
			}
			
			/* pop n things and fill in children */
			node = base_node(k, 0);
			g_ptr_array_set_size(node->children, n);
			for( i = n - 1; i >= 0; i-- )
				node->children->pdata[i] = g_ptr_array_remove_index(stack, stack->len - 1);
			
			/* push result */
			g_ptr_array_add(stack, node);
		}
	}

	if( stack->len > 1 )
	{
		raise_error("error parsing \"%s\": extra tokens left on stack\n", s);
		return 0;
	}
	else if( stack->len < 1 )
	{
		raise_error("error parsing \"%s\": empty policy\n", s);
		return 0;
	}

	root = g_ptr_array_index(stack, 0);

 	g_strfreev(toks);
 	g_ptr_array_free(stack, 0);

	return root;
}

bswabe_polynomial_t*
rand_poly( int deg, element_t zero_val )
{
	int i;
	bswabe_polynomial_t* q;

	q = (bswabe_polynomial_t*) malloc(sizeof(bswabe_polynomial_t));
	q->deg = deg;
	q->coef = (element_t*) malloc(sizeof(element_t) * (deg + 1));

	for( i = 0; i < q->deg + 1; i++ )
		element_init_same_as(q->coef[i], zero_val);

	element_set(q->coef[0], zero_val);

	for( i = 1; i < q->deg + 1; i++ )
 		element_random(q->coef[i]);

	return q;
}

void
eval_poly( element_t r, bswabe_polynomial_t* q, element_t x )
{
	int i;
	element_t s, t;

	element_init_same_as(s, r);
	element_init_same_as(t, r);

	element_set0(r);
	element_set1(t);

	for( i = 0; i < q->deg + 1; i++ )
	{
		/* r += q->coef[i] * t */
		element_mul(s, q->coef[i], t);
		element_add(r, r, s);

		/* t *= x */
		element_mul(t, t, x);
	}

	element_clear(s);
	element_clear(t);
}

void
fill_policy( bswabe_policy_t* p, bswabe_pub_t* pub, element_t e )
{
	int i;
	element_t r;
	element_t t;
	element_t h;

	element_init_Zr(r, pub->p);
	element_init_Zr(t, pub->p);
	element_init_G2(h, pub->p);

	p->q = rand_poly(p->k - 1, e);

	if( p->children->len == 0 )
	{
		element_init_G1(p->c,  pub->p);
		element_init_G2(p->cp, pub->p);

		element_from_string(h, p->attr);
		element_pow_zn(p->c,  pub->g, p->q->coef[0]);
		element_pow_zn(p->cp, h,      p->q->coef[0]);
	}
	else
		for( i = 0; i < p->children->len; i++ )
		{
			element_set_si(r, i + 1);
			eval_poly(t, p->q, r);
			fill_policy(g_ptr_array_index(p->children, i), pub, t);
		}

	element_clear(r);
	element_clear(t);
	element_clear(h);
}

void
bswabe_enc( bswabe_pub_t* pub, char* in_file, char* out_file, char* policy, int keep )
{
	bswabe_cph_t* cph;
 	element_t s;
 	
	int file_len;
	GByteArray* plt;
	GByteArray* cph_buf;
	GByteArray* aes_buf;
	element_t m;

	/* initialize */

	if((cph = malloc(sizeof(bswabe_cph_t))) == NULL){
		die("%s", bswabe_error());
		exit(0);
	}

	element_init_Zr(s, pub->p);
	element_init_GT(m, pub->p);
	element_init_GT(cph->cs, pub->p);
	element_init_G1(cph->c,  pub->p);
	cph->p = parse_policy_postfix(policy);

	/* compute */

 	element_random(m);
 	element_random(s);
	element_pow_zn(cph->cs, pub->g_hat_alpha, s);
	element_mul(cph->cs, cph->cs, m);

	element_pow_zn(cph->c, pub->h, s);

	fill_policy(cph->p, pub, s);
	
	/* version */
	cph->v_cp = pub->v_ek;
	
	free(policy);

	cph_buf = bswabe_cph_serialize(cph);
	bswabe_cph_free(cph);

	plt = suck_file(in_file);
	file_len = plt->len;
	aes_buf = aes_128_cbc_encrypt(plt, m);
	g_byte_array_free(plt, 1);
	element_clear(m);
	element_clear(s);

	write_cpabe_file(out_file, cph_buf, file_len, aes_buf);

	g_byte_array_free(cph_buf, 1);
	g_byte_array_free(aes_buf, 1);

	if( !keep )
		unlink(in_file);

}

void
check_sat( bswabe_policy_t* p, bswabe_prv_t* prv )
{
	int i, l;

	p->satisfiable = 0;
	if( p->children->len == 0 )
	{
		for( i = 0; i < prv->comps->len; i++ )
			if( !strcmp(g_array_index(prv->comps, bswabe_prv_comp_t, i).attr,
									p->attr) )
			{
				p->satisfiable = 1;
				p->attri = i;
				break;
			}
	}
	else
	{
		for( i = 0; i < p->children->len; i++ )
			check_sat(g_ptr_array_index(p->children, i), prv);

		l = 0;
		for( i = 0; i < p->children->len; i++ )
			if( ((bswabe_policy_t*) g_ptr_array_index(p->children, i))->satisfiable )
				l++;

		if( l >= p->k )
			p->satisfiable = 1;
	}
}

void
pick_sat_naive( bswabe_policy_t* p, bswabe_prv_t* prv )
{
	int i, k, l;

	assert(p->satisfiable == 1);

	if( p->children->len == 0 )
		return;

	p->satl = g_array_new(0, 0, sizeof(int));

	l = 0;
	for( i = 0; i < p->children->len && l < p->k; i++ )
		if( ((bswabe_policy_t*) g_ptr_array_index(p->children, i))->satisfiable )
		{
			pick_sat_naive(g_ptr_array_index(p->children, i), prv);
			l++;
			k = i + 1;
			g_array_append_val(p->satl, k);
		}
}

/* TODO there should be a better way of doing this */
bswabe_policy_t* cur_comp_pol;
int
cmp_int( const void* a, const void* b )
{
	int k, l;
	
	k = ((bswabe_policy_t*) g_ptr_array_index(cur_comp_pol->children, *((int*)a)))->min_leaves;
	l = ((bswabe_policy_t*) g_ptr_array_index(cur_comp_pol->children, *((int*)b)))->min_leaves;

	return
		k <  l ? -1 :
		k == l ?  0 : 1;
}

void
pick_sat_min_leaves( bswabe_policy_t* p, bswabe_prv_t* prv )
{
	int i, k, l;
	int* c;

	assert(p->satisfiable == 1);

	if( p->children->len == 0 )
		p->min_leaves = 1;
	else
	{
		for( i = 0; i < p->children->len; i++ )
			if( ((bswabe_policy_t*) g_ptr_array_index(p->children, i))->satisfiable )
				pick_sat_min_leaves(g_ptr_array_index(p->children, i), prv);

		c = alloca(sizeof(int) * p->children->len);
		for( i = 0; i < p->children->len; i++ )
			c[i] = i;

		cur_comp_pol = p;
		qsort(c, p->children->len, sizeof(int), cmp_int);

		p->satl = g_array_new(0, 0, sizeof(int));
		p->min_leaves = 0;
		l = 0;

		for( i = 0; i < p->children->len && l < p->k; i++ )
			if( ((bswabe_policy_t*) g_ptr_array_index(p->children, c[i]))->satisfiable )
			{
				l++;
				p->min_leaves += ((bswabe_policy_t*) g_ptr_array_index(p->children, c[i]))->min_leaves;
				k = c[i] + 1;
				g_array_append_val(p->satl, k);
			}
		assert(l == p->k);
	}
}

void
lagrange_coef( element_t r, GArray* s, int i )
{
	int j, k;
	element_t t;

	element_init_same_as(t, r);

	element_set1(r);
	for( k = 0; k < s->len; k++ )
	{
		j = g_array_index(s, int, k);
		if( j == i )
			continue;
		element_set_si(t, - j);
		element_mul(r, r, t); /* num_muls++; */
		element_set_si(t, i - j);
		element_invert(t, t);
		element_mul(r, r, t); /* num_muls++; */
	}

	element_clear(t);
}

void
dec_leaf_naive( element_t r, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	bswabe_prv_comp_t* c;
	element_t s;

	c = &(g_array_index(prv->comps, bswabe_prv_comp_t, p->attri));

	element_init_GT(s, pub->p);

	pairing_apply(r, p->c,  c->d,  pub->p); /* num_pairings++; */
	pairing_apply(s, p->cp, c->dp, pub->p); /* num_pairings++; */
	element_invert(s, s);
	element_mul(r, r, s); /* num_muls++; */

	element_clear(s);
}

void dec_node_naive( element_t r, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub );

void
dec_internal_naive( element_t r, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	int i;
	element_t s;
	element_t t;

	element_init_GT(s, pub->p);
	element_init_Zr(t, pub->p);

	element_set1(r);
	for( i = 0; i < p->satl->len; i++ )
	{
		dec_node_naive
			(s, g_ptr_array_index
			 (p->children, g_array_index(p->satl, int, i) - 1), prv, pub);
 		lagrange_coef(t, p->satl, g_array_index(p->satl, int, i));
		element_pow_zn(s, s, t); /* num_exps++; */
		element_mul(r, r, s); /* num_muls++; */
	}

	element_clear(s);
	element_clear(t);
}

void
dec_node_naive( element_t r, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	assert(p->satisfiable);
	if( p->children->len == 0 )
		dec_leaf_naive(r, p, prv, pub);
	else
		dec_internal_naive(r, p, prv, pub);
}

void
dec_naive( element_t r, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	dec_node_naive(r, p, prv, pub);
}

void
dec_leaf_merge( element_t exp, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	bswabe_prv_comp_t* c;
	element_t s;

	c = &(g_array_index(prv->comps, bswabe_prv_comp_t, p->attri));

	if( !c->used )
	{
		c->used = 1;
		element_init_G1(c->z,  pub->p);
		element_init_G1(c->zp, pub->p);
		element_set1(c->z);
		element_set1(c->zp);
	}

	element_init_G1(s, pub->p);

	element_pow_zn(s, p->c, exp); /* num_exps++; */
	element_mul(c->z, c->z, s); /* num_muls++; */

	element_pow_zn(s, p->cp, exp); /* num_exps++; */
	element_mul(c->zp, c->zp, s); /* num_muls++; */

	element_clear(s);
}

void dec_node_merge( element_t exp, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub );

void
dec_internal_merge( element_t exp, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	int i;
	element_t t;
	element_t expnew;

	element_init_Zr(t, pub->p);
	element_init_Zr(expnew, pub->p);

	for( i = 0; i < p->satl->len; i++ )
	{
 		lagrange_coef(t, p->satl, g_array_index(p->satl, int, i));
		element_mul(expnew, exp, t); /* num_muls++; */
		dec_node_merge(expnew, g_ptr_array_index
									 (p->children, g_array_index(p->satl, int, i) - 1), prv, pub);
	}

	element_clear(t);
	element_clear(expnew);
}

void
dec_node_merge( element_t exp, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	assert(p->satisfiable);
	if( p->children->len == 0 )
		dec_leaf_merge(exp, p, prv, pub);
	else
		dec_internal_merge(exp, p, prv, pub);
}

void
dec_merge( element_t r, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	int i;
	element_t one;
	element_t s;

	/* first mark all attributes as unused */
	for( i = 0; i < prv->comps->len; i++ )
		g_array_index(prv->comps, bswabe_prv_comp_t, i).used = 0;

	/* now fill in the z's and zp's */
	element_init_Zr(one, pub->p);
	element_set1(one);
	dec_node_merge(one, p, prv, pub);
	element_clear(one);

	/* now do all the pairings and multiply everything together */
	element_set1(r);
	element_init_GT(s, pub->p);
	for( i = 0; i < prv->comps->len; i++ )
		if( g_array_index(prv->comps, bswabe_prv_comp_t, i).used )
		{
			bswabe_prv_comp_t* c = &(g_array_index(prv->comps, bswabe_prv_comp_t, i));

			pairing_apply(s, c->z, c->d, pub->p); /* num_pairings++; */
			element_mul(r, r, s); /* num_muls++; */

			pairing_apply(s, c->zp, c->dp, pub->p); /* num_pairings++; */
			element_invert(s, s);
			element_mul(r, r, s); /* num_muls++; */
		}
	element_clear(s);
}

void
dec_leaf_flatten( element_t r, element_t exp,
									bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	bswabe_prv_comp_t* c;
	element_t s;
	element_t t;

	c = &(g_array_index(prv->comps, bswabe_prv_comp_t, p->attri));

	element_init_GT(s, pub->p);
	element_init_GT(t, pub->p);

	pairing_apply(s, p->c,  c->d,  pub->p); /* num_pairings++; */
	pairing_apply(t, p->cp, c->dp, pub->p); /* num_pairings++; */
	element_invert(t, t);
	element_mul(s, s, t); /* num_muls++; */
	element_pow_zn(s, s, exp); /* num_exps++; */

	element_mul(r, r, s); /* num_muls++; */

	element_clear(s);
	element_clear(t);
}

void dec_node_flatten( element_t r, element_t exp,
											 bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub );

void
dec_internal_flatten( element_t r, element_t exp,
											bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	int i;
	element_t t;
	element_t expnew;

	element_init_Zr(t, pub->p);
	element_init_Zr(expnew, pub->p);

	for( i = 0; i < p->satl->len; i++ )
	{
 		lagrange_coef(t, p->satl, g_array_index(p->satl, int, i));
		element_mul(expnew, exp, t); /* num_muls++; */
		dec_node_flatten(r, expnew, g_ptr_array_index
										 (p->children, g_array_index(p->satl, int, i) - 1), prv, pub);
	}

	element_clear(t);
	element_clear(expnew);
}

void
dec_node_flatten( element_t r, element_t exp,
									bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	assert(p->satisfiable);
	if( p->children->len == 0 )
		dec_leaf_flatten(r, exp, p, prv, pub);
	else
		dec_internal_flatten(r, exp, p, prv, pub);
}

void
dec_flatten( element_t r, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	element_t one;

	element_init_Zr(one, pub->p);

	element_set1(one);
	element_set1(r);

	dec_node_flatten(r, one, p, prv, pub);

	element_clear(one);
}

int
bswabe_dec( bswabe_pub_t* pub, char* prv_file, char* out_file, unsigned char* file_buffer)
{
	bswabe_prv_t* prv;
	int file_len;
	GByteArray* aes_buf;
	GByteArray* plt;
	GByteArray* cph_buf;
	bswabe_cph_t* cph;
	element_t t;
	element_t m;
	
	element_init_GT(m, pub->p);
	element_init_GT(t, pub->p);
	
	prv = bswabe_prv_unserialize(pub, suck_file(prv_file), 1);
	read_cpabe_file_from_buffer(&cph_buf, &file_len, &aes_buf, file_buffer);
	cph = bswabe_cph_unserialize(pub, cph_buf, 1);
	
	print_cph_t(cph);

	check_sat(cph->p, prv);
	if( !cph->p->satisfiable )
	{
		raise_error("cannot decrypt, attributes in key do not satisfy policy\n");
		return 0;
	}

/* 	if( no_opt_sat ) */
/* 		pick_sat_naive(cph->p, prv); */
/* 	else */
	pick_sat_min_leaves(cph->p, prv);

/* 	if( dec_strategy == DEC_NAIVE ) */
/* 		dec_naive(t, cph->p, prv, pub); */
/* 	else if( dec_strategy == DEC_FLATTEN ) */
	dec_flatten(t, cph->p, prv, pub);
/* 	else */
/* 		dec_merge(t, cph->p, prv, pub); */

	element_mul(m, cph->cs, t); /* num_muls++; */

	pairing_apply(t, cph->c, prv->d, pub->p); /* num_pairings++; */
	element_invert(t, t);
	element_mul(m, m, t); /* num_muls++; */
	
	bswabe_cph_free(cph);

	plt = aes_128_cbc_decrypt(aes_buf, m);
	g_byte_array_set_size(plt, file_len);
	g_byte_array_free(aes_buf, 1);

	spit_file(out_file, plt, 1);

	element_clear(t);
	element_clear(m);

	return 1;
}

uint32_t how_many_upd(char* upd_file)
{
	uint32_t iter;
	FILE* f;
	
	if( access( upd_file, F_OK ) == -1 )
		return (uint32_t) 0;
		
	if ((f = fopen(upd_file, "r") ) == NULL)
	{ 
		printf("Error in opening file (7)\n"); 
		exit(1); 
	} 
	fseek(f, 0L, SEEK_END);

	iter = (uint32_t) ftell(f) / UPD_LEN;
	fclose(f);
	return iter;
}

int
check_consistency(char* upd_file) // 1 if consistent, 0 otherwise
{
	FILE* f;
	unsigned char* buf;
	uint32_t current_version;
	uint32_t last_version;
	long pointer;
	long dim;
	int i;
	if((f = fopen(upd_file, "r")) == NULL){
		printf("Error in opening file (8)\n");
		exit(1);
	}
	if((buf = (unsigned char*) malloc(sizeof(uint32_t))) == NULL){
		printf("Error in malloc() (21)\n");
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
		if(current_version <= 0 || last_version != current_version - (uint32_t) 1)
			return 0;
		pointer += 160L;
		last_version = current_version;
		
	}
	fclose(f);
	free(buf);
	return 1;
}

void
bswabe_update_mk(bswabe_pub_t* pub, char* msk_file, char* upd_file)
{
	FILE* f;
	unsigned char* buf;
	int i;
	bswabe_upd_t* new_node;
	element_t beta;
	element_t old_beta;
	
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

}

void
bswabe_update_pk(char* pub_file, char* upd_file)
{
	unsigned char* buf;
	long upds;
	FILE* f_upd;
	FILE* f_pub;
	
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
}

void
bswabe_update_dk(bswabe_pub_t* pub, char* prv_file, char* upd_file)
{
	element_t exp;
	element_t current_exp;
	element_t base;
	unsigned char* buf;
	uint32_t version;
	uint32_t current_version;
	int i;
	long dim;
	long pointer;
	FILE* f_prv;
	FILE* f_upd;
	
	if(!check_consistency(upd_file)){
		printf("Error in version (3)\n");
		exit(1);
	}
	
	if((f_prv = fopen(prv_file, "r+")) == NULL || (f_upd = fopen(upd_file, "r")) == NULL) {
		printf("Error in opening file (3)\n");
		exit(1);
	}
	
	// Fetch decryption key version
	if((buf = (unsigned char*) malloc(sizeof(uint32_t))) == NULL){
		printf("Error in malloc() (6)\n");
		exit(1);
	}
	fseek(f_prv, -4L, SEEK_END);
	
	fread(buf, 1, 4L, f_prv);
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
			printf("Error in version (4)\n");
			exit(1);
		}
	}
	free(buf);
	
	// Fetch all u_cp(s)
	element_init_Zr(exp, pub->p);
		element_init_Zr(current_exp, pub->p);
	if((buf = (unsigned char*) malloc(20)) == NULL){
		printf("Error in malloc() (7)\n");
		exit(1);
	}
	element_set1(exp);
	while(TRUE){
		if(pointer > dim){
			free(buf);
			if((buf = (unsigned char*) malloc(sizeof(uint32_t))) == NULL){
				printf("Error in malloc() (8)\n");
				exit(1);
			}
			pointer -= 8L;
			fseek(f_upd, pointer, SEEK_SET);
			fread(buf, 1, 4L, f_upd);
			fseek(f_prv, -4L, SEEK_END);
			fwrite(buf, 1, 4L, f_prv);
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
	element_init_G2(base, pub->p);
	if((buf = (unsigned char*) malloc(128)) == NULL){
		printf("Error in malloc() (9)\n");
		exit(1);
	}
	fseek(f_prv, 4L, SEEK_SET);
	fread(buf, 1, 128L, f_prv);
	element_from_bytes(base, buf);
	element_pow_zn(base, base, exp);
	element_to_bytes(buf, base);
	fseek(f_prv, 4L, SEEK_SET);
	fwrite(buf, 1, 128L, f_prv);
	free(buf);
	
	element_clear(exp);
	element_clear(current_exp);
	element_clear(base);
	fclose(f_upd);
	fclose(f_prv);
}

void
bswabe_update_cp(bswabe_pub_t* pub, char* cph_file, char* upd_file)
{
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
	
	if(!check_consistency(upd_file)){
		printf("Error in version (5)\n");
		exit(1);
	}
	
	read_cpabe_file(cph_file, &cph_buf, &file_len, &aes_buf);

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
				return;
			break;
		}
		pointer += 160L;
		if(pointer > dim){
			printf("Error in version (6)\n");
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
}

void
bswabe_update_partial_updates(bswabe_pub_t* pub, char* updates_file, char* upd_file)
{
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
		printf("Error in version (7)\n");
		exit(1);
	}
	if((f_updates = fopen(updates_file, "r+")) == NULL || (f_upd = fopen(upd_file, "r")) == NULL) {
		printf("Error in opening file (5)\n");
		exit(1);
	}
	// Fetch decryption key version
	if((buf = (unsigned char*) malloc(sizeof(uint32_t))) == NULL){
		printf("Error in malloc() (14)\n");
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
			printf("Error in version (8)\n");
			exit(1);
		}
	}
	free(buf);
	
	// Fetch all u_cp(s)
	element_init_Zr(exp, pub->p);
	element_init_Zr(current_exp, pub->p);
	if((buf = (unsigned char*) malloc(20)) == NULL){
		printf("Error in malloc() (15)\n");
		exit(1);
	}
	element_set1(exp);
	while(TRUE){
		if(pointer > dim){
			free(buf);
			if((buf = (unsigned char*) malloc(sizeof(uint32_t))) == NULL){
				printf("Error in malloc() (16)\n");
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
				printf("Error in malloc() (17)\n");
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
	element_init_G2(base, pub->p);
	if((buf = (unsigned char*) malloc(128)) == NULL){
		printf("Error in malloc() (18)\n");
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

void
bswabe_update_pub_and_prv_keys_partial(unsigned char* partial_updates, char* pub_file, char* prv_file)
{
	/* TODO update the error messages */
	FILE* f_pub;
	FILE* f_prv;
	
	if( (f_prv = fopen(prv_file, "r+")) == NULL || (f_pub = fopen(pub_file, "r+")) == NULL) {
		fprintf(stderr, "Error in opening file (6). Error: %s\n", strerror(errno));
		exit(1);
	}
	
	// Update decryption key version
	fseek(f_prv, -4L, SEEK_END);
	fwrite(partial_updates, 1, 4L, f_prv);
	
	//Update public key version
	fseek(f_pub, -4L, SEEK_END);
	fwrite(partial_updates, 1, 4L, f_pub);
	
	// Update h field in public key
	fseek(f_pub, 496L, SEEK_SET);
	fwrite(partial_updates + 4, 1, 128L, f_pub);
	
	// Update d field in private key
	fseek(f_prv, 4L, SEEK_SET);
	fwrite(partial_updates + 132, 1, 128L, f_prv);
	
	
	fclose(f_prv);
	fclose(f_pub);

}

void print_upd_t(bswabe_upd_t *head) {
	if(head == NULL){
		printf("UPD not initilized yet\n");
		return;
	}
	bswabe_upd_t *current_node = head;
	printf("Printing UPD\n");
	while ( current_node != NULL) {
		printf("Node at version %d:\n", current_node->v_uk);
		element_printf("u_cp (%d bytes): %B\n", sizeof(current_node->u_cp), current_node->u_cp);
		element_printf("u_pk (%d bytes): %B\n", sizeof(current_node->u_pk), current_node->u_pk);
		printf("v_uk: %u\n", current_node->v_uk);
		current_node = current_node->next;
  }
}

void print_pub_t(bswabe_pub_t* pub){
	printf("Printing Public Key (version %u)\n", pub->v_ek);
	element_printf("pub->h: %B\n", pub->h);
	element_printf("pub->g: %B\n", pub->g);
	element_printf("pub->g_hat_alpha: %B\n", pub->g_hat_alpha);
	element_printf("pub->gp: %B\n\n", pub->gp);
}

void print_msk_t(bswabe_msk_t* msk){
	printf("Printing Master Key\n");
	element_printf("beta: %B\n", msk->beta);
	element_printf("g_alpha: %B\n", msk->g_alpha);
	printf("v_mk: %u\n\n", msk->v_mk);
}
void print_prv_t(bswabe_prv_t* prv){
	printf("Printing Private Key (Decryption key)\n");
	element_printf("d: %B\n", prv->d);
	printf("Version %u\n\n", prv->v_dk);
}
void print_cph_t(bswabe_cph_t* cph){
	printf("Printing Ciphertext\n");
	element_printf("c: %B\n", cph->c);
	element_printf("cs: %B\n", cph->cs);
	printf("Version %u\n\n", cph->v_cp);
}
