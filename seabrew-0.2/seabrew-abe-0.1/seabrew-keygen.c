#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>

#include "common.h"
#include "policy_lang.h"
#include "seabrew.h"

char* usage =
"Usage: seabrew-abe-keygen [OPTION ...] PUB_KEY MASTER_KEY ATTR [ATTR ...]\n"
"\n"
"Generate a key with the listed attributes using public key PUB_KEY and\n"
"master secret key MASTER_KEY. Output will be written to the file\n"
"\"priv_key\" unless the -o option is specified.\n"
"Additionally, set the generated key's version to the MASTER_KEY's version.\n"
"\n"
"Attributes come in two forms: non-numerical and numerical. Non-numerical\n"
"attributes are simply any string of letters, digits, and underscores\n"
"beginning with a letter.\n"
"\n"
"Numerical attributes are specified as `attr = N', where N is a non-negative\n"
"integer less than 2^64 and `attr' is another string. The whitespace around\n"
"the `=' is optional. One may specify an explicit length of k bits for the\n"
"integer by giving `attr = N#k'. Note that any comparisons in a policy given\n"
"to seabrew-abe-enc(1) must then specify the same number of bits, e.g.,\n"
"`attr > 5#12'.\n"
"\n"
"The keywords `and', `or', and `of', are reserved for the policy language\n"
"of seabrew-abe-enc (1) and may not be used for either type of attribute.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -o, --output FILE        write resulting key to FILE\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
"";

/*
	TODO ensure we don't give out the same attribute more than once (esp
	as different numerical values)
*/

char*  pub_file = 0;
char*  msk_file = 0;
char** attrs    = 0;

char*  out_file = "priv_key";

gint
comp_string( gconstpointer a, gconstpointer b)
{
	return strcmp(a, b);
}

void
parse_args( int argc, char** argv )
{
	int i;
	GSList* alist;
	GSList* ap;
	int n;

	alist = 0;
	for( i = 1; i < argc; i++ )
		if(      !strcmp(argv[i], "-h") || !strcmp(argv[i], "--help") )
		{
			printf("%s", usage);
			exit(0);
		}
		else if( !strcmp(argv[i], "-v") || !strcmp(argv[i], "--version") )
		{
			printf(SEABREW_ABE_VERSION, "-seabrew-keygen");
			exit(0);
		}
		else if( !strcmp(argv[i], "-o") || !strcmp(argv[i], "--output") )
		{
			if( ++i >= argc )
				die(usage);
			else
				out_file = argv[i];
		}
		else if( !strcmp(argv[i], "-d") || !strcmp(argv[i], "--deterministic") )
		{
			pbc_random_set_deterministic(0);
		}
		else if( !pub_file )
		{
			pub_file = argv[i];
		}
		else if( !msk_file )
		{
			msk_file = argv[i];
		}
		else
		{
			parse_attribute(&alist, argv[i]);
		}

	if( !pub_file || !msk_file || !alist )
		die(usage);

	alist = g_slist_sort(alist, comp_string);
	n = g_slist_length(alist);

	attrs = malloc((n + 1) * sizeof(char*));

	i = 0;
	for( ap = alist; ap; ap = ap->next )
		attrs[i++] = ap->data;
	attrs[i] = 0;
}

int
main( int argc, char** argv )
{
	seabrew_bswabe_pub_t* pub;
	seabrew_bswabe_msk_t* msk;
	seabrew_bswabe_prv_t* prv;
	seabrew_bswabe_d_t* d;

	parse_args(argc, argv);
	
	pbc_random_set_deterministic(10);
	
	pub = seabrew_bswabe_pub_unserialize(suck_file(pub_file), 1);
	msk = seabrew_bswabe_msk_unserialize(pub, suck_file(msk_file), 1);
	
	prv = seabrew_bswabe_keygen(pub, msk, attrs);
	spit_file(out_file, seabrew_bswabe_prv_serialize(prv), 1);
	
	d = seabrew_bswabe_extract_d(pub, prv);
	spit_file(g_strdup_printf("%s.d", out_file), seabrew_bswabe_d_serialize(d), 1);
	
	seabrew_bswabe_msk_free(msk);
	free(msk);
	
	seabrew_bswabe_pub_free(pub);
	free(pub);
	
	free(prv);
	free(d);

	return 0;
}
