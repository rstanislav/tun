#ifndef CRYPTO_H_
#define CRYPTO_H_

#include <openssl/rsa.h>

struct keyhdr
{
    unsigned short nlen;
    unsigned short elen;
    unsigned short dlen;
    unsigned short plen;
    unsigned short qlen;
    unsigned short dmp1len;
    unsigned short dmq1len;
    unsigned short iqmplen;
};

struct pubhdr
{
    unsigned short nlen;
    unsigned short elen;
};

size_t crypto_key_len(RSA *r);
int crypto_pack_key(RSA *r,
                    struct keyhdr *h,
                    unsigned char *data,
                    size_t len);
RSA *crypto_unpack_key(const struct keyhdr *h,
                       const unsigned char *data);
size_t crypto_pub_len(RSA *r);
int crypto_pack_pub(RSA *r,
                    struct pubhdr *h,
                    unsigned char *data,
                    size_t len);
RSA *crypto_unpack_pub(const struct pubhdr *h,
                       const unsigned char *data);
char *crypto_hash_str(const unsigned char *data,
                      unsigned long n);

#endif
