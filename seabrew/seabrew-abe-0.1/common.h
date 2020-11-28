/*
	Include glib.h and pbc.h before including this file.

	This contains data structures and procedures common throughout the
	tools.
*/

/*
	TODO if ssl sha1 not available, use built in one (sha1.c)
*/

char*       suck_file_str( char* file );
char*       suck_stdin();
GByteArray* suck_file( char* file ); //

void        spit_file( char* file, GByteArray* b, int free ); //

void read_cpabe_file( char* file,    GByteArray** cph_buf,
											int* file_len, GByteArray** aes_buf );

void write_cpabe_file( char* file,   GByteArray* cph_buf,
											 int file_len, GByteArray* aes_buf );

void die(char* fmt, ...);

GByteArray* aes_128_cbc_encrypt( GByteArray* pt, element_t k );
GByteArray* aes_128_cbc_decrypt( GByteArray* ct, element_t k );

#define SEABREW_ABE_VERSION PACKAGE_NAME "%s " PACKAGE_VERSION "\n" \
"\n" \
"Report bugs to University of Pisa.\n"
