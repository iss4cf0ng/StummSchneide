// rc4.cpp

#include "crypto_interface.h"

static const unsigned char KEY[] = "MyKey";

#define KEYLEN sizeof(KEY)/sizeof(*KEY)

typedef struct { unsigned char S[256]; int i, j; } RC4Ctx;

static void _init(void *ctx, const unsigned char *key, int keylen)
{
    RC4Ctx *c = (RC4Ctx *)ctx;

    // S-box
    for (int i = 0; i < 256; i++)
        c->S[i] = i;

    int j = 0;
    for (int i = 0; i < 256; i++)
    {
        j = (j + c->S[i] + key[i % keylen]) % 256;
        unsigned char t = c->S[i];
        c->S[i] = c->S[j];
        c->S[j] = t;
    }

    c->i = c->j = 0;
}

static void _crypt(void *ctx, char *data, int len)
{
    RC4Ctx *c = (RC4Ctx *)ctx;
    int i = c->i;
    int j = c->j;

    for (int n = 0; n < len; n++)
    {
        i = (i + 1) % 256;
        j = (j + c->S[i]) % 256;

        unsigned char t = c->S[i];
        c->S[i] = c->S[j];
        c->S[j] = t;

        data[n] ^= c->S[(c->S[i] + c->S[j]) % 256];
    }

    c->i = i;
    c->j = j;
}

CryptoOps CRYPTO = { _init, _crypt };

const unsigned char *crypto_key() { return KEY; }
int crypto_keylen() { return KEYLEN; }
