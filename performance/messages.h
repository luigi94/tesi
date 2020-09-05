#if defined (__cplusplus)
extern "C" {
#endif
/*
*	ID is the user identifier
*	type is used to discriminate the request type:
*	0 -> ...
*/
#define MAX_USER_LENGTH 64
typedef struct{
	char ID[64];
	uint8_t type;
} Request;

#if defined (__cplusplus)
} // extern "C"
#endif
