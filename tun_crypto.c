#include "crypto.h"

#ifndef GEN_DEPS
static const struct
{
    struct keyhdr hdr;
    unsigned char data[];
} binkey = {
#include "priv.key"
};
#endif

RSA *privkey = NULL;

void crypto_init(void)
{
    privkey = crypto_unpack_key(&binkey.hdr, binkey.data);
}

