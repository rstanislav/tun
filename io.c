#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "pktqueue.h"
#include "events.h"
#include "peer.h"

static int listen_mode;
static struct pktqueue rx_pool;
static struct pktqueue tx_queue;
static struct dispatch evt_dispatch;
static struct event *socket_event;

#define PKT_POOL_SZ 1024
#define PKT_BUFF_SZ 1500

static void rx_complete(struct pkt *p, void *priv)
{
    (void)priv;

    p->pkt_size = 0;
    pktqueue_enqueue(&rx_pool, p);
    event_control(&evt_dispatch, socket_event, EVCTL_READ_RESTART);
}

void socket_tx_schedule(struct pkt *p, void *priv)
{
    struct sockaddr_in *dest = priv;

    pkt_set_dest(p, dest);
    pktqueue_enqueue(&tx_queue, p);
    event_control(&evt_dispatch, socket_event, EVCTL_WRITE_RESTART);
}

static void rx_handler(struct pkt *p, struct sockaddr_in *src)
{
    struct peer *peer;

    peer = peer_lookup(src);

    if (!peer && listen_mode) {
        peer = peer_create(&evt_dispatch, src);
    }

    peer_rx(peer, p);
}

static int socket_event_handler(int fd, unsigned short flags, void *priv)
{
    (void)priv;
    struct pkt *p;
    int rc;

    if (flags & EVENT_READ) {
        p = pktqueue_dequeue(&rx_pool);
        if (p) {
            struct sockaddr_in src;
            socklen_t addrlen = sizeof (src);

            rc = recvfrom(fd, p->buff, p->buff_size, 0,
                          (struct sockaddr *)&src, &addrlen);
            if (rc <= 0)
                fprintf(stderr, "socket: recv error.\n");
            p->pkt_size = rc;
            pkt_set_compl(p, rx_complete, NULL);
            rx_handler(p, &src);
        } else {
            rc = event_control(&evt_dispatch, socket_event, EVCTL_READ_STALL);
            if (rc)
                return DISPATCH_ABORT;
        }
    }

    if (flags & EVENT_WRITE) {
        p = pktqueue_dequeue(&tx_queue);
        if (p) {
            struct sockaddr_in *dest = pkt_get_dest(p);

            rc = sendto(fd, p->buff, p->pkt_size, 0,
                        (struct sockaddr *)dest, sizeof (*dest));
            if (rc - p->pkt_size)
                fprintf(stderr, "socket: send error.\n");

            pkt_complete(p);
        } else {
            rc = event_control(&evt_dispatch, socket_event, EVCTL_WRITE_STALL);
            if (rc)
                return DISPATCH_ABORT;
        }
    }

    return DISPATCH_CONTINUE;
}

int io_dispatch(int sockfd, struct sockaddr_in *remote)
{
    struct pkt *p;
    int rc;
    int i;
    struct peer *serv;

    pktqueue_init(&rx_pool);
    pktqueue_init(&tx_queue);
    for (i = 0; i < PKT_POOL_SZ; i++) {
        p = pkt_alloc(PKT_BUFF_SZ);
        if (!p)
            break;
        pktqueue_enqueue(&rx_pool, p);
    }

    rc = dispatch_init(&evt_dispatch);
    if (rc)
        goto error;

    socket_event = event_create(&evt_dispatch, sockfd, EVENT_READ,
                                socket_event_handler, NULL);
    if (!socket_event)
        goto cleanup;

    listen_mode = !remote;

    if (remote) {
        serv = peer_create(&evt_dispatch, remote);
        if (!serv)
            goto cleanup;
        peer_tryconnect(serv);
    }

    rc = event_dispatch(&evt_dispatch);

    if (serv) {
        peer_destroy(serv);
    }

cleanup:
    dispatch_cleanup(&evt_dispatch);
error:
    while ((p = pktqueue_dequeue(&rx_pool))) {
        pkt_free(p);
    }
    while ((p = pktqueue_dequeue(&tx_queue))) {
        pkt_free(p);
    }
    return rc;
}

