/*
  Include glib.h and pbc.h before including this file. Note that this
  file should be included at most once.
*/

#if defined (__cplusplus)
extern "C" {
#endif

/*
  A public key.
*/
typedef struct bswabe_pub_s bswabe_pub_t;

/*
  A master secret key.
*/
typedef struct bswabe_msk_s bswabe_msk_t;

/*
  An update key.
*/
typedef struct bswabe_upd_s bswabe_upd_t;

/*
  A private key.
*/
typedef struct bswabe_prv_s bswabe_prv_t;

/*
  A ciphertext. Note that this library only handles encrypting a
  single group element, so if you want to encrypt something bigger,
  you will have to use that group element as a symmetric key for
  hybrid encryption (which you do yourself).
*/
typedef struct bswabe_cph_s bswabe_cph_t;

/*
  Generate a public key and corresponding master secret key, and
  assign the *pub and *msk pointers to them. The space used may be
  later freed by calling bswabe_pub_free(*pub) and
  bswabe_msk_free(*msk).
*/
void bswabe_setup( bswabe_pub_t** pub, bswabe_msk_t** msk);

/*
  Generate a private key with the given set of attributes. The final
  argument should be a null terminated array of pointers to strings,
  one for each attribute.
*/
bswabe_prv_t* bswabe_keygen( bswabe_pub_t* pub,
                             bswabe_msk_t* msk,
                             char** attributes );

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
bswabe_cph_t* bswabe_enc( bswabe_pub_t* pub, element_t m, char* policy );

/*
  Decrypt the specified ciphertext using the given private key,
  filling in the provided element m (which need not be initialized)
  with the result.

  Returns true if decryption succeeded, false if this key does not
  satisfy the policy of the ciphertext (in which case m is unaltered).
*/
int bswabe_dec( bswabe_pub_t* pub, bswabe_prv_t* prv,
                bswabe_cph_t* cph, element_t m );

/*
	Print the Master Key
*/
void print_msk_t(bswabe_msk_t* msk);

/*
	Print the Public Key
*/
void print_pub_t(bswabe_pub_t* pub);

/*
	Print the Private (Decryption) Key
*/
void print_prv_t(bswabe_prv_t* prv);

/*
	Print all Updated key versions
*/
void print_upd_t(bswabe_upd_t *head);

/*
	Print the cipher-text
*/
void print_cph_t(bswabe_cph_t* cph);

/*
	Update the master secret key and generates a new update key
*/
void bswabe_update_mk(bswabe_pub_t* pub, char* msk_file, char* upd_file);

/*
	Update de private Public key
*/
void bswabe_update_pk(char* pub_file, char* upd_file);

/*
	Update the decryption key
*/
void bswabe_update_dk(bswabe_pub_t* pub, char* prv_file, char* upd_file);

/*
	Udate the cipher-text
*/
void bswabe_update_cp(bswabe_pub_t* pub, char* prv_file, char* upd_file);

/*
	Update the Partial Decryption Key
*/
void bswabe_update_partial_dk(bswabe_pub_t* pub, char* partial_prv_file, char* upd_file);

/*
  Exactly what it seems.
*/
GByteArray* bswabe_pub_serialize( bswabe_pub_t* pub );
GByteArray* bswabe_msk_serialize( bswabe_msk_t* msk );
GByteArray* bswabe_prv_serialize( bswabe_prv_t* prv );
GByteArray* bswabe_cph_serialize( bswabe_cph_t* cph );

GByteArray* bswabe_prv_extract_partial_and_serialize( bswabe_prv_t* prv );

GByteArray* bswabe_upd_serialize( bswabe_upd_t* upd );
void serialize_element( GByteArray* b, element_t e );
void unserialize_element( GByteArray* b, int* offset, element_t e );
char* unserialize_string( GByteArray* b, int* offset );

/*
  Also exactly what it seems. If free is true, the GByteArray passed
  in will be free'd after it is read.
*/
bswabe_pub_t* bswabe_pub_unserialize( GByteArray* b, int free );
bswabe_msk_t* bswabe_msk_unserialize( bswabe_pub_t* pub, GByteArray* b, int free );
bswabe_prv_t* bswabe_prv_unserialize( bswabe_pub_t* pub, GByteArray* b, int free );
bswabe_cph_t* bswabe_cph_unserialize( bswabe_pub_t* pub, GByteArray* b, int free );

bswabe_upd_t* bswabe_upd_unserialize( bswabe_pub_t* pub, GByteArray* b, char* upd_file, int free );

/*
  Again, exactly what it seems.
*/
void bswabe_pub_free( bswabe_pub_t* pub );
void bswabe_msk_free( bswabe_msk_t* msk );
void bswabe_prv_free( bswabe_prv_t* prv );
void bswabe_cph_free( bswabe_cph_t* cph );

void bswabe_upd_free( bswabe_upd_t* upd );

/*
  Return a description of the last error that occured. Call this after
  bswabe_enc or bswabe_dec returns 0. The returned string does not
  need to be free'd.
*/
char* bswabe_error();

#if defined (__cplusplus)
} // extern "C"
#endif
