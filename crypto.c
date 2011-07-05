#include <string.h>

#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/bn.h>

#include "crypto.h"

int crypto_pack_key(RSA *r, struct keypair *kp)
{
    int rc = 0;

    memset(kp, 0, sizeof (*kp));
    rc |= BN_bn2bin(r->n, kp->pub.n);
    rc |= BN_bn2bin(r->e, kp->pub.e);
    rc |= BN_bn2bin(r->d, kp->d);
    rc |= BN_bn2bin(r->p, kp->p);
    rc |= BN_bn2bin(r->q, kp->q);
    rc |= BN_bn2bin(r->dmp1, kp->dmp1);
    rc |= BN_bn2bin(r->dmq1, kp->dmq1);
    rc |= BN_bn2bin(r->iqmp, kp->iqmp);

    return rc;
}

