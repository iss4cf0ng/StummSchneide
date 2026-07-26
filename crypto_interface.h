// crypto_interface.h

typedef struct crypto_interface
{
    void (*init)(void* ctx, const unsigned char* key, int key_len);
    void (*crypt)(void* ctx, char* data, int len);
} CryptoOps;

extern CryptoOps CRYPTO;
