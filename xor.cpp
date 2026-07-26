// xor.cpp

#include "crypto_interface.h"

static const unsigned char KEY[] = "XORKEY";
#define KEYLEN sizeof(KEY)/sizeof(*KEY);

typedef struct { const unsigned char *key; int klen; int pos; } XORCtx;

static void _init(void *ctx, const unsigned char *key, int klen)
{
    XORCtx *c = (XORCtx *)ctx;
    c->key = key;
    c->klen = klen;
    c->pos = 0;
}

static void _crypt(void *ctx, unsigned char *data, int len)
{
    XORCtx *c = (XORCtx *)ctx;
    for (int n = 0 ; n < len; n++)
    {
        data[n] ^= c->key[c->pos % c->klen];
        c->pos++;
    }
}

CryptoOps CRYPTO = { _init, _crypt };

const unsigned char *crypto_key() { return KEY; }
int crypto_keylen() { return KEYLEN };