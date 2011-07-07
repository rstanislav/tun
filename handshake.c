#include <strings.h>
#include <linux/if_tun.h>
#include <stdio.h>

#include "peer.h"
#include "crypto.h"

extern RSA *privkey;

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
    hdr->proto = htons(HANDSHAKE_PROTO_ID);
    pkt->pkt_size = sizeof (struct tun_pi) + sizeof (struct pubhdr);
    pkt->pkt_size += crypto_pack_pub(privkey, pubhdr,
                                     (void *)(pubhdr + 1),
                                     pkt->buff_size - pkt->pkt_size);
    pkt_set_compl(pkt, handshake_pkt_complete, NULL);

    peer_send(p, pkt);
}

void handshake_init(struct peer *p)
{
    handshake_send_pub(p);
}

void handshake_reset(struct peer *p)
{
    (void)p;
}

int handshake_accept(struct peer *p, struct pkt *pkt)
{
    struct tun_pi *hdr = (struct tun_pi *)pkt->buff;

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
        fprintf(stdout, "Received public key:\n");
        RSA_print_fp(stdout, p->pubkey, 4);

        return 1;
    }

    return -1;
}

int handshake_connected(struct peer *p, struct pkt *pkt)
{
    struct tun_pi *hdr = (struct tun_pi *)pkt->buff;

    (void)p;
    (void)hdr;

    return -1;
}

