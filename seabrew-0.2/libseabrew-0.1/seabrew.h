#if defined (__cplusplus)
extern "C" {
#endif

#include "bswabe.h"

typedef struct seabrew_bswabe_pub_s
{
	bswabe_pub_t* pub_f;
	uint32_t version;
} seabrew_bswabe_pub_t;

typedef struct seabrew_bswabe_msk_s
{
	bswabe_msk_t* msk_f;
	uint32_t version;
} seabrew_bswabe_msk_t;

typedef struct seabrew_bswabe_prv_s
{
	bswabe_prv_t* prv_f;
	uint32_t version;
} seabrew_bswabe_prv_t;

typedef struct seabrew_bswabe_cph_s
{
	bswabe_cph_t* cph_f;
	uint32_t version;
} seabrew_bswabe_cph_t;	

struct seabrew_bswabe_upd_s
{
	
	element_t u_cp;    /* Z_r */
	element_t u_pk; /* G_1 */
	/* element_t u_dk; // is the inverse of u_cp */
	
	/* version */
	uint32_t v_uk;
	
	struct seabrew_bswabe_upd_s* next;
	
};

typedef struct seabrew_bswabe_upd_s seabrew_bswabe_upd_t;

typedef struct seabrew_bswabe_partial_updates_s
{
	uint32_t version;
	element_t pub_h;
	element_t prv_d;

} seabrew_bswabe_partial_updates_t;

typedef struct seabrew_bswabe_u_cp_s
{
	uint32_t version;
	element_t u_cp;

} seabrew_bswabe_u_cp_t;

typedef struct seabrew_bswabe_u_pk_s
{
	uint32_t version;
	element_t u_pk;

} seabrew_bswabe_u_pk_t;

typedef struct seabrew_bswabe_u_dk_s
{
	uint32_t version;
	element_t u_dk;

} seabrew_bswabe_u_dk_t;

/*
  Generate a public key and corresponding master secret key, and
  assign the *pub and *msk pointers to them. The space used may be
  later freed by calling bswabe_pub_free(*pub) and
  bswabe_msk_free(*msk).
*/
void seabrew_bswabe_setup(seabrew_bswabe_pub_t** pub, seabrew_bswabe_msk_t** msk);

/*
  Generate a private key with the given set of attributes. The final
  argument should be a null terminated array of pointers to strings,
  one for each attribute.
*/
seabrew_bswabe_prv_t* seabrew_bswabe_keygen(seabrew_bswabe_pub_t* pub, seabrew_bswabe_msk_t* msk, char** attributes, seabrew_bswabe_partial_updates_t** partial_updates);

/*
  Pick a random group element and encrypt it under the specified
  access policy. The resulting ciphertext is returned and the
  element_t given as an argument (which need not be initialized) is
  set to the random group element.

  After using this function, it is normal to extract the random data
  in m using the pbc functions element_length_in_bytes and
  element_to_bytes and use it as a key for hybrid encryption.

  The policy is specified as a simple string which encodes a postorder
  traversal of threshold tree defining the access policy. As an
  example,

    "foo bar fim 2of3 baf 1of2"

  specifies a policy with two threshold gates and four leaves. It is
  not possible to specify an attribute with whitespace in it (although
  "_" is allowed).

  Numerical attributes and any other fancy stuff are not supported.

  Returns null if an error occured, in which case a description can be
  retrieved by calling bswabe_error().
*/
seabrew_bswabe_cph_t* seabrew_bswabe_enc(seabrew_bswabe_pub_t* pub, element_t m, char* policy );

/*
  Decrypt the specified ciphertext using the given private key,
  filling in the provided element m (which need not be initialized)
  with the result.

  Returns true if decryption succeeded, false if this key does not
  satisfy the policy of the ciphertext (in which case m is unaltered).
*/
int seabrew_bswabe_dec(seabrew_bswabe_pub_t* pub, seabrew_bswabe_prv_t* prv, seabrew_bswabe_cph_t* cph, element_t m );

/*
	Update the master secret key and generates (or updates if the
	passed file exists and it is valid) a new update-key.
*/
void seabrew_bswabe_update_mk(seabrew_bswabe_pub_t* pub, char* msk_file, char* upd_file);

/*
	Update the public using the informations contained in the update key
*/
void seabrew_bswabe_update_pk(char* pub_file, seabrew_bswabe_u_pk_t* u_pk);

/*
	Udate the cipher-text
*/
void seabrew_bswabe_update_cp(seabrew_bswabe_pub_t* pub, char* prv_file, char* upd_file);
void seabrew_bswabe_update_cp_bis(seabrew_bswabe_pub_t* pub, char* cph_file, seabrew_bswabe_u_cp_t* u_cp);

/*
	Udate the private key
*/
void seabrew_bswabe_update_dk(seabrew_bswabe_pub_t* pub, char* prv_file, seabrew_bswabe_u_dk_t* u_dk);

/*
	Update the Partial Updates
*/
void seabrew_bswabe_update_partial_updates(seabrew_bswabe_pub_t* pub, char* updates_file, char* upd_file);

/*
	Build the new prv_key from the old prv_key and the partial prv_key
*/
void seabrew_bswabe_update_pub_and_prv_keys_partial(char* partial_updates_file, char* pub, char* prv_file);

/*
	Extract the partial update key from start to end
*/
seabrew_bswabe_upd_t* extract(seabrew_bswabe_upd_t* upd, uint32_t start, uint32_t end);

/*
	Extract the u_cp field (Eq. (12)) from update key upd
*/
seabrew_bswabe_u_cp_t* extract_u_cp(seabrew_bswabe_upd_t* upd, seabrew_bswabe_u_cp_t* u_cp, int reset);

/*
	Extract the u_dk field (Eq. (11, first equation)) from update key upd
*/
seabrew_bswabe_u_dk_t* extract_u_dk(seabrew_bswabe_upd_t* upd, seabrew_bswabe_u_dk_t* u_cp, int reset);

/*
	Extract the u_pk field (middle rquation of (8)) from update key upd
*/
seabrew_bswabe_u_pk_t* extract_u_pk(seabrew_bswabe_upd_t* upd);

/*
  Exactly what it seems.
*/
GByteArray* seabrew_bswabe_pub_serialize(seabrew_bswabe_pub_t* pub );
GByteArray* seabrew_bswabe_msk_serialize(seabrew_bswabe_msk_t* msk );
GByteArray* seabrew_bswabe_prv_serialize(seabrew_bswabe_prv_t* prv );
GByteArray* seabrew_bswabe_cph_serialize(seabrew_bswabe_cph_t* cph );
GByteArray* seabrew_bswabe_upd_serialize(seabrew_bswabe_upd_t* upd );
GByteArray* seabrew_bswabe_partial_updates_serialize(seabrew_bswabe_partial_updates_t* partial_updates);
GByteArray* seabrew_bswabe_u_cp_serialize(seabrew_bswabe_u_cp_t* u_cp );
void serialize_uint32(GByteArray* b, uint32_t k);
void serialize_element( GByteArray* b, element_t e );

/*
  Also exactly what it seems. If free is true, the GByteArray passed
  in will be free'd after it is read.
*/
seabrew_bswabe_pub_t* seabrew_bswabe_pub_unserialize( GByteArray* b, int free );
seabrew_bswabe_msk_t* seabrew_bswabe_msk_unserialize( seabrew_bswabe_pub_t* pub, GByteArray* b, int free );
seabrew_bswabe_prv_t* seabrew_bswabe_prv_unserialize( seabrew_bswabe_pub_t* pub, GByteArray* b, int free );
seabrew_bswabe_cph_t* seabrew_bswabe_cph_unserialize( seabrew_bswabe_pub_t* pub, GByteArray* b, int free );
seabrew_bswabe_upd_t* seabrew_bswabe_upd_unserialize(seabrew_bswabe_pub_t* pub, GByteArray* b, int free );
seabrew_bswabe_u_cp_t* seabrew_bswabe_u_cp_unserialize(seabrew_bswabe_pub_t* pub, GByteArray* b, int free );
seabrew_bswabe_u_pk_t* seabrew_bswabe_u_pk_unserialize(seabrew_bswabe_pub_t* pub, GByteArray* b, int free );
uint32_t unserialize_uint32( GByteArray* b, int* offset );
void unserialize_element( GByteArray* b, int* offset, element_t e );

/*
  Again, exactly what it seems.
*/
void seabrew_bswabe_pub_free( seabrew_bswabe_pub_t* pub );
void seabrew_bswabe_msk_free( seabrew_bswabe_msk_t* msk );
void seabrew_bswabe_prv_free( seabrew_bswabe_prv_t* prv );
void seabrew_bswabe_cph_free( seabrew_bswabe_cph_t* cph );
void seabrew_bswabe_upd_free( seabrew_bswabe_upd_t* upd );
void seabrew_bswabe_u_cp_free( seabrew_bswabe_u_cp_t* u_cp );

void update_file( char* file, GByteArray* b, int free );

void print_seabrew_upd_t(seabrew_bswabe_upd_t* head);
void print_seabrew_pub_t(seabrew_bswabe_pub_t* pub);
void print_seabrew_msk_t(seabrew_bswabe_msk_t* msk);
void print_seabrew_prv_t(seabrew_bswabe_prv_t* prv);
void print_seabrew_cph_t(seabrew_bswabe_cph_t* cph);

#if defined (__cplusplus)
}
#endif
