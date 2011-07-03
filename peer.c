#include <stdio.h>
#include <unistd.h>
#include <linux/if_tun.h>

#include "pktqueue.h"
#include "events.h"
#include "iface.h"
#include "peer.h"

#ifndef IP_MTU
# define IP_MTU 14
#endif

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

static int mtu_discover(struct sockaddr_in *addr)
{
    int sock;
    int mtu;
    int rc;
    socklen_t len = sizeof (mtu);

    /* HACK: To discover MTU, Create and connect back a socket to the host */
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return 1500;
    rc = connect(sock, (struct sockaddr *) addr, sizeof (*addr));
    if (rc) {
        fprintf(stderr, "%s: connect() failed: %s\n", __func__,
                strerror(errno));
        mtu = 1500;
        goto close;
    }

    rc = getsockopt(sock, IPPROTO_IP, IP_MTU, &mtu, &len);
    if (rc) {
        fprintf(stderr, "Error Getting MTU: %s\n", strerror(errno));
        mtu = 1500;
    }

close:
    close(sock);

    return mtu;
}

void socket_tx_schedule(struct pkt *, void *);

static int peer_iface_init(struct peer *p)
{
    int mtu;

    /*
     * Reuse MTU value minus the distance between Transport IP header and
     * encapsulated IP header.
     */
    mtu = mtu_discover(&p->addr) -
        (8 + sizeof (struct tun_pi));

    p->iface = iface_create(1024, mtu);
    if (!p->iface) {
        fprintf(stderr, "Can't create interface.");
        return -1;
    }
    iface_event_start(p->iface, p->dispatch);
    iface_set_tx(p->iface, socket_tx_schedule, &p->addr);

    return 0;
}

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
    if (p->state == PEER_STATE_UNKNOWN) {
        if (is_hello(pkt)) {
            olleh_send(p);
            peer_iface_init(p);
            p->state = PEER_STATE_CONNECTED;
        }
    } else if (p->state == PEER_STATE_TRYCONNECT) {
        if (is_olleh(pkt)) {
            peer_iface_init(p);
            p->state = PEER_STATE_CONNECTED;
        } else
            p->state = PEER_STATE_UNKNOWN;
    } else if (p->state == PEER_STATE_CONNECTED) {
        iface_rx_schedule(p->iface, pkt);
    }
}

