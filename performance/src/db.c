#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <glib.h>
#include <pbc.h>
#include <regex.h>

#include "bswabe.h"
#include "common.h"
#include "policy_lang.h"
#include "db.h"

#define UNUSED(x) (void)(x)

void open_db(sqlite3** const restrict db){
	if (sqlite3_open(DATABASE, &(*db)) != SQLITE_OK) {
		fprintf(stderr, "Cannot open database. Error: %s\n", sqlite3_errmsg(*db));
		sqlite3_close(*db);
		exit(1);
	}
}
void close_db(sqlite3* db){
	if (sqlite3_close(db) != SQLITE_OK) {
		fprintf(stderr, "Error in closing database. Error: %s\n", sqlite3_errmsg(db));
		exit(1);
	}
}
void check_error(const int rc, sqlite3* db) {
	if (rc != SQLITE_OK) {
		printf("Error #%d: %s\n", rc, sqlite3_errmsg(db));
		sqlite3_close(db);
		exit(rc);
	}
}

static int callback(void *ui, int argc, char **argv, char **azColName) {
	size_t size;
	sqlite3_int64 tmp;
	
	UNUSED(argc);
	UNUSED(azColName);
	
	size = strlen(argv[0]) > (size_t) MAX_ENCRYPTED_DEC_KEY_NAME_LEN ? (size_t) MAX_ENCRYPTED_DEC_KEY_NAME_LEN : strlen(argv[0]);
	memcpy((void*)((user_info*)ui)->encryped_decryption_key_name, (void*)argv[0], size);
	((user_info*)ui)->encryped_decryption_key_name[size] = '\0';
	
	size = strlen(argv[1]) > (size_t) MAX_FILE_NAME_LEN ? (size_t) MAX_FILE_NAME_LEN : strlen(argv[1]);
	memcpy((void*)((user_info*)ui)->encrypted_file_name, (void*)argv[1], size);
	((user_info*)ui)->encrypted_file_name[size] = '\0';
	
	size = strlen(argv[2]) > (size_t) MAX_ATTRIBUTE_SET_LEN ? (size_t) MAX_ATTRIBUTE_SET_LEN : strlen(argv[2]);
	memcpy((void*)((user_info*)ui)->current_attribute_set, (void*)argv[2], size);
	((user_info*)ui)->current_attribute_set[size] = '\0';
	
  tmp = strtoull(argv[3], NULL, 0);
	if(tmp > (sqlite3_int64)UINT_MAX){
		free(ui);
		exit(1);
	} 
	((user_info*)ui)->key_version = (uint32_t)tmp;
	
  tmp = strtoull(argv[4], NULL, 0);
	if(tmp > (sqlite3_int64)UINT_MAX){
		free(ui);
		exit(1);
	} 
	((user_info*)ui)->updated_key_version = (uint32_t)tmp;
	
  tmp = strtoull(argv[5], NULL, 0);
	if(tmp > (sqlite3_int64)UINT_MAX){
		free(ui);
		exit(1);
	} 
	((user_info*)ui)->ciphertext_version = (uint32_t)tmp;
	
  tmp = strtoull(argv[6], NULL, 0);
	if(tmp > (sqlite3_int64)UINT_MAX){
		free(ui);
		exit(1);
	} 
	((user_info*)ui)->updated_ciphertext_version = (uint32_t)tmp;

	return 0;
}

void get_user_info(sqlite3* db, const char* const restrict user, user_info* restrict* const restrict ui){
	char *err_msg = 0;
	char *sql;
	int rc;
	
	sql = sqlite3_mprintf("SELECT encrypted_decryption_key, encrypted_file, current_attribute_set, key_version, updated_key_version, ciphertext_version, updated_ciphertext_version FROM Users WHERE User = '%s';", user);
	if((*ui = (user_info*)malloc(sizeof(user_info))) == NULL){
		fprintf(stderr, "Error in allocating memory for user info. Error: %s\n", strerror(errno));
		exit(1);
	}
	rc = sqlite3_exec(db, sql, callback, (void*)*ui, &err_msg);
	check_error(rc, db);

	if (rc != SQLITE_OK ){
		fprintf(stderr, "Failed to select data\n");
		fprintf(stderr, "SQL error: %s\n", err_msg);
		sqlite3_free(err_msg);
		sqlite3_free(sql);
		sqlite3_close(db);
		exit(1);
	}
	sqlite3_free(err_msg);
	sqlite3_free(sql);
}

void initialize_db(sqlite3* db){
	char *err_msg = 0;

	char *sql = "DROP TABLE IF EXISTS Users;"
		"CREATE TABLE Users(User CHAR(32) NOT NULL PRIMARY KEY, encrypted_decryption_key CHAR(32) NOT NULL, encrypted_file CHAR(32) NOT NULL, current_attribute_set CHAR(256) NOT NULL, "
		"key_version INT UNISGNED NOT NULL, updated_key_version INT UNSIGNED NOT NULL, ciphertext_version INT UNISGNED NOT NULL, updated_ciphertext_version INT UNSIGNED NOT NULL);" 
		"INSERT INTO Users VALUES(\"kevin\", \"kevin_priv_key.enc\",\"to_send.pdf.cpabe\", \"Audi_v_0 'year_v_0 = 2017' X5_v_0 'ECU_1_v_0 = 324' 'ECU_2_v_0 = 215' 'ECU_3_v_0 = 123'\", 0, 0, 0, 0);";
		
	open_db(&db);

	if (sqlite3_exec(db, sql, 0, 0, &err_msg) != SQLITE_OK ) {

		fprintf(stderr, "SQL error: %s\n", err_msg);

		sqlite3_free(err_msg);
	}
	   
	close_db(db);

}

int update_attribute_set(sqlite3* db, const char* const restrict user, const char* const restrict new_attribute_set){

	char* sql;
	char* err_msg = "";
	
	sql = sqlite3_mprintf("UPDATE Users SET current_attribute_set = \"%s\" WHERE User = \"%s\";", new_attribute_set, user);
	
	if (sqlite3_exec(db, sql, 0, 0, &err_msg) != SQLITE_OK ) {
		fprintf(stderr, "SQL error: %s\n", err_msg);
		sqlite3_free(err_msg);
		sqlite3_free(sql);
		return 0;
	}
	sqlite3_free(err_msg);
	sqlite3_free(sql);
	return 1;
}

int update_version(sqlite3* db, const char* const restrict user, const int type, const uint32_t new_version){

	char* sql;
	char* err_msg = "";
	
	switch(type){
		case KEY_VERSION:
			sql = sqlite3_mprintf("UPDATE Users SET key_version = %u WHERE User = \"%s\";", new_version, user); break;
		case UPDATED_KEY_VERSION:
			sql = sqlite3_mprintf("UPDATE Users SET updated_key_version = %u WHERE User = \"%s\";", new_version, user); break;
		case CIPHERTEXT_VERSION:
			sql = sqlite3_mprintf("UPDATE Users SET ciphertext_version = %u WHERE User = \"%s\";", new_version, user); break;
		case UPDATED_CIPHERTEXT_VERSION:
			sql = sqlite3_mprintf("UPDATE Users SET updated_ciphertext_version = %u WHERE User = \"%s\";", new_version, user); break;
		default:
			fprintf(stderr, "Unknown updated operation (%d)\n", type);
			return 0;
	}
	if (sqlite3_exec(db, sql, 0, 0, &err_msg) != SQLITE_OK ) {
		fprintf(stderr, "SQL error: %s\n", err_msg);
		sqlite3_free(err_msg);
		sqlite3_free(sql);
		return 0;
	}
	sqlite3_free(err_msg);
	sqlite3_free(sql);
	return 1;
}

void make_attribute_set(char* const restrict attributes, const attribute_s* const restrict attr_s, const uint32_t version){
	/* This is a simple testing attribute set */
	sprintf(attributes, "%1$s_v_%7$u 'year_v_%7$u = %2$u' %3$s_v_%7$u 'ECU_1_v_%7$u = %4$u' 'ECU_2_v_%7$u = %5$u' 'ECU_3_v_%7$u = %6$u'", attr_s->brand, attr_s->year, attr_s->model, attr_s->ECU_1, attr_s->ECU_2, attr_s->ECU_3, version);
}

gint comp_string( gconstpointer a, gconstpointer b){
	return strcmp(a, b);
}
void bswabe_keygen_bis(const char* const restrict attribute_set, char* const restrict msk_file, bswabe_pub_t* restrict pub, char* const restrict out_file){
	char** attrs;
	GSList* alist;
	GSList* ap;
	guint n;
	int i;
	
	size_t attributes_str_len;
	size_t start;
	size_t size;
	char c;
	char* tmp;

	alist = 0;
	attributes_str_len = strlen(attribute_set);
	tmp = NULL;
	for(size_t i = 0; i < attributes_str_len; i++){
		c = attribute_set[i];
		if( c == ' ' ){
			continue;
		}else if(c == '\'' ){
			start = ++i;
			while( attribute_set[i] != '\'' ){
				i++;
			}
			size = i + 1 - start;
			if((tmp = (char*)malloc(size)) == NULL){
				fprintf(stderr, "Error in allocating memory for attribute. Error: %s\n", strerror(errno));
				exit(1);
			}
			memcpy((void*)tmp, (void*)(attribute_set + start), size);
			tmp[size - 1] = '\0';
			parse_attribute(&alist, tmp);
		}else{
			start = i;
			while( attribute_set[i] != '\'' && attribute_set[i] != ' ' ){
				i++;
			}
			size = i + 1 - start;
			if((tmp = (char*)malloc(size)) == NULL){
				fprintf(stderr, "Error in allocating memory for attribute. Error: %s\n", strerror(errno));
				exit(1);
			}
			memcpy((void*)tmp, (void*)(attribute_set + start), size);
			tmp[size - 1] = '\0';
			parse_attribute(&alist, tmp);
		}
	}
	free(tmp);
	if(!alist ){
		fprintf(stderr, "Error in creating attribute list. Error: %s\n", strerror(errno));
		exit(1);
	}

	alist = g_slist_sort(alist, comp_string);
	n = g_slist_length(alist);
	
	if((attrs = malloc((n + 1) * sizeof(char*))) == NULL){
		fprintf(stderr, "Error in allocating memory for attributes set string. Error: %s\n", strerror(errno));
		exit(1);
	}

	i = 0;
	for( ap = alist; ap; ap = ap->next )
		attrs[i++] = ap->data;
	attrs[i] = 0;
	
	bswabe_keygen(pub, msk_file, out_file, NULL, attrs);
	for(guint k = 0; k < n; k++){
		free(attrs[k]);
	}
	free(attrs);
	g_slist_free(ap);
	g_slist_free(alist);
}

void make_version_regex(const uint32_t arg, char* restrict* const restrict buffer) {
	if((*buffer = (char*)malloc( 3UL + (size_t) snprintf(NULL, 0, "%u", arg))) == NULL){
		fprintf(stderr, "Error in allocating memory for appending characters. Error: %s\n", strerror(errno));
		exit(1);
	}
	sprintf(*buffer, "_v_%u", arg);
}

char *str_replace(char* restrict orig, const char* const restrict rep, const char* restrict with) {
	char *result;
	char *ins;
	char *tmp;
	unsigned long len_rep;
	unsigned long len_with;
	unsigned long len_front;
	size_t count;

	if (!orig || !rep) return NULL;
	len_rep = strlen(rep);
	
	if (len_rep == 0) return NULL; 
	
	if (!with) with = "";
	
	len_with = strlen(with);

	ins = orig;
	for (count = 0; (tmp = strstr(ins, rep)); ++count) ins = tmp + len_rep;

	if ((tmp = result = (char*)malloc(strlen(orig) + (len_with - len_rep)*count + 1UL)) == NULL) return NULL;

	while (count--) {
		ins = strstr(orig, rep);
		len_front = ins - orig;
		tmp = strncpy(tmp, orig, len_front) + len_front;
		tmp = strcpy(tmp, with) + len_with;
		orig += len_front + len_rep; // move to next "end of rep"
	}
	strcpy(tmp, orig);
	return result;
}

void get_policy_or_attribute_version(char* const restrict source, const char* const restrict regex_string, uint32_t* const restrict res){
  regex_t regex;
  regmatch_t matches;
  char * cursor;
  size_t size;

	if (regcomp(&regex, regex_string, REG_EXTENDED)){
		printf("Could not compile regular expression.\n");
		exit(1);
	}

	cursor = source;
	char* tmp;
	for (size_t m = 0; m < (size_t)MAX_MATCHES; m++) {
		if (regexec(&regex, cursor, 1, &matches, 0))
			break;
		
		size = matches.rm_eo - matches.rm_so - 3UL <= 10UL ? matches.rm_eo - matches.rm_so - 3UL : 10UL;
		
		if((tmp = (char*)malloc(size)) == NULL){
			fprintf(stderr, "Error in allocatin memory for string match %lu. Error: %s\n", m + 1UL, strerror(errno));
			exit(1);
		}
		uint64_t tmp64;
		uint32_t tmp32;
		memcpy((void*)tmp, (void*)(cursor + matches.rm_so + 3UL), size);
		tmp[size] = '\0';
		
  	tmp64 = strtoull(tmp, NULL, 0);
  	if(tmp64 > UINT_MAX){
  		fprintf(stderr, "Version beyond maximum allowed\n");
  		exit(1);
		}
  	tmp32 = (uint32_t)tmp64;
  	if(m == 0)
  		*res = tmp32;
		else{
			if(*res != tmp32){
				fprintf(stderr, "This policy contains different version of attributes and this is not allowed\n");
				exit(1);
			}else{
				*res = tmp32;
			}
		}
		if(tmp) free(tmp);
		cursor += matches.rm_eo;
	}
	regfree(&regex);
}
