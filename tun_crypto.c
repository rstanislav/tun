#include <unistd.h>

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

#define MAGIC_IVEC {0, 1, 3, 3, 7, 0, 0, 255}

void crypto_init(void)
{
    int fd;
    int rc;
    unsigned char r[16];

    privkey = crypto_unpack_key(&binkey.hdr, binkey.data);

    RAND_seed(r, 16);
    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        return;
    do {
        rc = read(fd, r, 16);
        if (rc != 16)
            return;
        RAND_seed(r, 16);

        rc = RAND_bytes(r, 16);
    } while (!rc);
    close (fd);
}

void peer_encrypt(struct pkt *pkt, void *priv)
{
    struct peer *p = priv;
    unsigned char ivec[8] = MAGIC_IVEC;
    int num;

    BF_cfb64_encrypt((unsigned char *)pkt->buff, (unsigned char *)pkt->buff,
                     pkt->pkt_size, &p->key, ivec, &num, BF_ENCRYPT);

    p->tx(pkt, &p->addr);
}

void peer_decrypt(struct peer *p, struct pkt *pkt)
{
    unsigned char ivec[8] = MAGIC_IVEC;
    int num;

    BF_cfb64_encrypt((unsigned char *)pkt->buff, (unsigned char *)pkt->buff,
                     pkt->pkt_size, &p->key, ivec, &num, BF_DECRYPT);

    iface_rx_schedule(p->iface, pkt);
}

