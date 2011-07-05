#ifndef CRYPTO_H_
#define CRYPTO_H_

#include <openssl/rsa.h>

struct keypair
{
    struct pubkey
    {
        unsigned char n[256];
        unsigned char e[4];
    } pub;
    unsigned char d[256];
    unsigned char p[128];
    unsigned char q[128];
    unsigned char dmp1[128];
    unsigned char dmq1[128];
    unsigned char iqmp[128];
};

int crypto_pack_key(RSA *r, struct keypair *kp);

#endif
