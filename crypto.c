#include <string.h>

#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/bn.h>

#include "crypto.h"

size_t crypto_key_len(RSA *r)
{
    size_t l = 0;

    l += BN_num_bytes(r->n);
    l += BN_num_bytes(r->e);
    l += BN_num_bytes(r->d);
    l += BN_num_bytes(r->p);
    l += BN_num_bytes(r->q);
    l += BN_num_bytes(r->dmp1);
    l += BN_num_bytes(r->dmq1);
    l += BN_num_bytes(r->iqmp);

    return l;
}

int crypto_pack_key(RSA *r, struct keyhdr *h,
                    unsigned char *data, size_t len)
{
    int i = 0;
    size_t l = 0;

    l += h->nlen = BN_num_bytes(r->n);
    l += h->elen = BN_num_bytes(r->e);
    l += h->dlen = BN_num_bytes(r->d);
    l += h->plen = BN_num_bytes(r->p);
    l += h->qlen = BN_num_bytes(r->q);
    l += h->dmp1len = BN_num_bytes(r->dmp1);
    l += h->dmq1len = BN_num_bytes(r->dmq1);
    l += h->iqmplen = BN_num_bytes(r->iqmp);

    if (l > len)
        return -1;

    i += BN_bn2bin(r->n, data + i);
    i += BN_bn2bin(r->e, data + i);
    i += BN_bn2bin(r->d, data + i);
    i += BN_bn2bin(r->p, data + i);
    i += BN_bn2bin(r->q, data + i);
    i += BN_bn2bin(r->dmp1, data + i);
    i += BN_bn2bin(r->dmq1, data + i);
    i += BN_bn2bin(r->iqmp, data + i);

    return i;
}

RSA *crypto_unpack_key(const struct keyhdr *h,
                       const unsigned char *data)
{
    RSA *r;
    int i = 0;

    r = RSA_new();
    if (!r)
        return NULL;

    r->n = BN_bin2bn(data + i, h->nlen, r->n);
    i += h->nlen;
    r->e = BN_bin2bn(data + i, h->elen, r->e);
    i += h->elen;
    r->d = BN_bin2bn(data + i, h->dlen, r->d);
    i += h->dlen;
    r->p = BN_bin2bn(data + i, h->plen, r->p);
    i += h->plen;
    r->q = BN_bin2bn(data + i, h->qlen, r->q);
    i += h->qlen;
    r->dmp1 = BN_bin2bn(data + i, h->dmp1len, r->dmp1);
    i += h->dmp1len;
    r->dmq1 = BN_bin2bn(data + i, h->dmq1len, r->dmq1);
    i += h->dmq1len;
    r->iqmp = BN_bin2bn(data + i, h->iqmplen, r->iqmp);

    return r;
}

size_t crypto_pub_len(RSA *r)
{
    size_t l = 0;

    l += BN_num_bytes(r->n);
    l += BN_num_bytes(r->e);

    return l;
}

int crypto_pack_pub(RSA *r, struct pubhdr *h,
                    unsigned char *data, size_t len)
{
    int i = 0;
    size_t l = 0;

    l += h->nlen = BN_num_bytes(r->n);
    l += h->elen = BN_num_bytes(r->e);

    if (l > len)
        return -1;

    i += BN_bn2bin(r->n, data + i);
    i += BN_bn2bin(r->e, data + i);

    return i;
}

RSA *crypto_unpack_pub(const struct pubhdr *h,
                       const unsigned char *data)
{
    RSA *r;
    int i = 0;

    r = RSA_new();
    if (!r)
        return NULL;

    r->n = BN_bin2bn(data + i, h->nlen, r->n);
    i += h->nlen;
    r->e = BN_bin2bn(data + i, h->elen, r->e);

    return r;
}

char *crypto_hash_str(const unsigned char *data,
                      unsigned long n)
{
    unsigned char digest[SHA_DIGEST_LENGTH];
    char *ret;
    int i, j;

    SHA1(data, n, digest);

    ret = malloc(SHA_DIGEST_LENGTH * 2 + 1);
    if (!ret)
        return NULL;

    j = 0;
    for (i = 0; i < SHA_DIGEST_LENGTH; i++)
        j += sprintf(ret + j, "%02x", digest[i]);

    return ret;
}

