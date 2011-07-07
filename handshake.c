#include <strings.h>
#include <linux/if_tun.h>
#include <stdio.h>

#include "peer.h"
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

static RSA *privkey = NULL;

/*
 * Crytographic handshake sketch:
 *
 *    TODO: Add some form of authentification.
 *
 *
 * (CONN_RESET)                                     (CONN_RESET)
 * (CONN_REQUEST)
 *                             pubA
 *                 A -----------------------> B
 *
 *                                                  (CONN_ACCEPT)
 *
 *                             pubB
 *                 A <----------------------- B
 *
 *         accept(pubB)
 *         a = rand()
 *         ca = encrypt(pubB,a)
 *         sa = sign(privA,a)
 *
 *                            ca + sa
 *                 A -----------------------> B
 *
 *                                   a = decrypt(privB,ca)
 *                                       verify(pubA,sa,a)
 *                                              b = rand()
 *                                    cb = encrypt(pubA,b)
 *                                      sb = sign(privB,b)
 *                                             key = a ^ b
 *                                                     (CONNECTED)
 *
 *                            cb + sb
 *                 A <----------------------- B
 *
 *         b = decrypt(privA,cb)
 *         verify(pubB,b)
 *         key = a ^ b
 * (CONNECTED)
 *
 */

static void handshake_pkt_complete(struct pkt *pkt, void *priv)
{
    (void)priv;

    pkt_free(pkt);
}

static void handshake_send_pub(struct peer *p)
{
    struct pkt *pkt;
    struct tun_pi *hdr;
    struct pubhdr *pubhdr;

    pkt = pkt_alloc(sizeof (struct tun_pi) +
                    sizeof (struct pubhdr) +
                    crypto_pub_len(privkey));
    if (!pkt)
        return;
    hdr = (struct tun_pi *)pkt->buff;
    pubhdr = (struct pubhdr *)(hdr + 1);
    hdr->proto = htons(TUN_PROTO_ID);
    pkt->pkt_size = sizeof (struct tun_pi);
    pkt->pkt_size += crypto_pack_pub(privkey, pubhdr,
                                     (void *)(pubhdr + 1),
                                     pkt->buff_size - pkt->pkt_size);
    pkt_set_compl(pkt, handshake_pkt_complete, NULL);

    peer_send(p, pkt);
}

void handshake_init(struct peer *p)
{
    if (privkey == NULL)
        privkey = crypto_unpack_key(&binkey.hdr, binkey.data);

    handshake_send_pub(p);
}

void handshake_reset(struct peer *p)
{
    (void)p;
}

int handshake_accept(struct peer *p, struct pkt *pkt)
{
    struct tun_pi *hdr = (struct tun_pi *)pkt->buff;

    if (privkey == NULL)
        privkey = crypto_unpack_key(&binkey.hdr, binkey.data);

    if (!p->pubkey) {
        struct pubhdr *phdr = (struct pubhdr *)(hdr + 1);
        unsigned char *data = (void *)(phdr + 1);

        p->pubkey = crypto_unpack_pub(phdr, data);

        handshake_send_pub(p);

        return 1;
    }

    return -1;
}

int handshake_request(struct peer *p, struct pkt *pkt)
{
    struct tun_pi *hdr = (struct tun_pi *)pkt->buff;

    if (!p->pubkey) {
        struct pubhdr *phdr = (struct pubhdr *)(hdr + 1);
        unsigned char *data = (void *)(phdr + 1);

        p->pubkey = crypto_unpack_pub(phdr, data);

        return 1;
    }

    return -1;
}

int handshake_connected(struct peer *p, struct pkt *pkt)
{
    struct tun_pi *hdr = (struct tun_pi *)pkt->buff;

    (void)p;
    (void)hdr;

    return 0;
}

