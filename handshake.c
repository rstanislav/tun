#include <strings.h>
#include <linux/if_tun.h>
#include <stdio.h>

#include "peer.h"

static void handshake_pkt_complete(struct pkt *pkt, void *priv)
{
    (void)priv;

    pkt_free(pkt);
}

static struct pkt *handshake_pkt_build(void *data, size_t size)
{
    struct pkt *pkt;
    struct tun_pi *hdr;

    pkt = pkt_alloc(size + sizeof (struct tun_pi));
    if (!pkt)
        return NULL;
    pkt->pkt_size = size + sizeof (struct tun_pi);
    hdr = (struct tun_pi *)pkt->buff;
    hdr->proto = htons(0x1337);
    memcpy(hdr + 1, data, size);
    pkt_set_compl(pkt, handshake_pkt_complete, NULL);

    return pkt;
}

void handshake_init(struct peer *p)
{
    struct pkt *pkt;

    pkt = handshake_pkt_build("HELLO", 5);
    peer_send(p, pkt);
}

void handshake_reset(struct peer *p)
{
    struct pkt *pkt;

    pkt = handshake_pkt_build("RESET", 5);
    peer_send(p, pkt);
}

int handshake_accept(struct peer *p, struct pkt *pkt)
{
    struct tun_pi *hdr = (struct tun_pi *)pkt->buff;

    if ((pkt->pkt_size - sizeof (*hdr) >= 5) &&
        !memcmp(hdr + 1, "HELLO", 5)) {

        pkt = handshake_pkt_build("HELLO", 5);
        peer_send(p, pkt);

        return 1;
    }

    return -1;
}

int handshake_request(struct peer *p, struct pkt *pkt)
{
    struct tun_pi *hdr = (struct tun_pi *)pkt->buff;

    (void)p;

    if ((pkt->pkt_size - sizeof (*hdr) >= 5) &&
        !memcmp(hdr + 1, "HELLO", 5)) {

        return 1;
    }

    return -1;
}

int handshake_connected(struct peer *p, struct pkt *pkt)
{
    struct tun_pi *hdr = (struct tun_pi *)pkt->buff;

    (void)p;

    if ((pkt->pkt_size - sizeof (*hdr) >= 5) &&
        !memcmp(hdr + 1, "RESET", 5)) {

        return -1;
    }

    fprintf(stderr, "Unknown protocol message received while connected\n");

    return 0;
}

