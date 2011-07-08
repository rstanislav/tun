#include "crypto.h"
#include "peer.h"
#include "iface.h"

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

void peer_encrypt(struct pkt *pkt, void *priv)
{
    struct peer *p = priv;

    p->tx(pkt, &p->addr);
}

void peer_decrypt(struct peer *p, struct pkt *pkt)
{
    
    iface_rx_schedule(p->iface, pkt);
}

