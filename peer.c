#include <stdio.h>

#include "pktqueue.h"
#include "events.h"
#include "peer.h"

LIST_HEAD(, peer) peer_list = {NULL};

struct peer *peer_lookup(struct sockaddr_in *addr)
{
    struct peer *tmp, *p = NULL;

    LIST_FOREACH(tmp, &peer_list, link) {
        if (!memcmp(&tmp->addr, addr, sizeof (addr))) {
            p = tmp;
            break;
        }
    }

    return p;
}

struct peer *peer_create(struct dispatch *d, struct sockaddr_in *addr)
{
    struct peer *p;

    p = calloc(1, sizeof (*p));
    if (!p)
        return NULL;

    p->dispatch = d;
    p->state = PEER_STATE_UNKNOWN;
    memcpy(&p->addr, addr, sizeof (*addr));
    LIST_INSERT_HEAD(&peer_list, p, link);

    return p;
}

void peer_destroy(struct peer *p)
{
    if (p->iface) {
        iface_event_stop(p->iface);
        iface_destroy(p->iface);
    }

    LIST_REMOVE(p, link);
    free(p);
}

void socket_tx_schedule(struct pkt *, void *);

static void hello_complete(struct pkt *pkt, void *priv)
{
    (void)priv;

    pkt_free(pkt);
}

static int is_hello(struct pkt *pkt)
{
    if (pkt->pkt_size < 6)
        return 0;

    return !strncmp(pkt->buff, "HELLO\n", 6);
}

static int is_olleh(struct pkt *pkt)
{
    if (pkt->pkt_size < 6)
        return 0;

    return !strncmp(pkt->buff, "OLLEH\n", 6);
}

static void hello_send(struct peer *p)
{
    struct pkt *pkt;

    pkt = pkt_alloc(6);
    pkt_set_compl(pkt, hello_complete, NULL);
    pkt->pkt_size = 6;
    strncpy(pkt->buff, "HELLO\n", 6);
    socket_tx_schedule(pkt, &p->addr);
}

static void olleh_send(struct peer *p)
{
    struct pkt *pkt;

    pkt = pkt_alloc(6);
    pkt_set_compl(pkt, hello_complete, NULL);
    pkt->pkt_size = 6;
    strncpy(pkt->buff, "OLLEH\n", 6);
    socket_tx_schedule(pkt, &p->addr);
}

void peer_tryconnect(struct peer *p)
{

    hello_send(p);
    p->state = PEER_STATE_TRYCONNECT;
}

void peer_rx(struct peer *p, struct pkt *pkt)
{
    if (p->state == PEER_STATE_UNKNOWN &&
        is_hello(pkt)) {
        olleh_send(p);
        p->state = PEER_STATE_CONNECTED;
        goto iface_create;
    }

    if (p->state == PEER_STATE_TRYCONNECT &&
        is_olleh(pkt)) {
        p->state = PEER_STATE_CONNECTED;
        goto iface_create;
    }

    if (p->state == PEER_STATE_CONNECTED) {
        goto iface_rx;
    }

    p->state = PEER_STATE_UNKNOWN;

    return;
iface_create:
    p->iface = iface_create(1024, 1500);
    if (!p->iface) {
        fprintf(stderr, "Can't create interface.");
        return;
    }
    iface_event_start(p->iface, p->dispatch);
    iface_set_tx(p->iface, socket_tx_schedule, &p->addr);
    return;
iface_rx:
    iface_rx_schedule(p->iface, pkt);
}

