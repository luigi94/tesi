#define ITERATIONS 1
#define REQUESTS 12

#if SHA_BITS == 512
#define ALGORITHM EVP_sha3_512()
#define DIGEST_LEN SHA512_DIGEST_LENGTH
#elif SHA_BITS == 384
#define ALGORITHM EVP_sha3_384()
#define DIGEST_LEN SHA384_DIGEST_LENGTH
#endif