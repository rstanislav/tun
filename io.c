#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "pktqueue.h"
#include "events.h"

#define RX_POOL_SIZE 1024
#define TX_POOL_SIZE 1024

static struct pktqueue rx_pool;
static struct pktqueue tx_pool;

struct event *pktcompl_event_create(struct dispatch *d);

static int init_pools(size_t pkt_sz)
{
    int i;

    pktqueue_init(&rx_pool);
    pktqueue_init(&tx_pool);

    for (i = 0; i <  RX_POOL_SIZE; i++) {
        struct pkt *p = pkt_alloc(pkt_sz);

        pktqueue_enqueue(&rx_pool, p);
    }

    for (i = 0; i <  TX_POOL_SIZE; i++) {
        struct pkt *p = pkt_alloc(pkt_sz);

        pktqueue_enqueue(&tx_pool, p);
    }

    return 0;
}

static int setnonblock(int fd)
{
    long fl;

    fl = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static void send_compl(struct pkt *p, void *priv, size_t count)
{
    struct pktqueue *pool = (struct pktqueue *)priv;

    p->pkt_size = 0;
    pktqueue_enqueue(pool, p);
}

static int sock_recv(int fd, unsigned short flags, void *priv)
{
    struct pkt *p;
    int rc;
    /* FIXME */
    int tun_fd = (int)priv;

    p = pktqueue_dequeue(&rx_pool);
    if (!p) {
        fprintf(stderr, "RX packet pool exhausted\n");
        return DISPATCH_ABORT;
    }

    rc = read(fd, p->buff, p->buff_size);
    if (rc == -1) {
        fprintf(stderr, "recv() error: %s\n", strerror(errno));
        return DISPATCH_ABORT;
    }
    if (rc == 0) {
        fprintf(stderr, "recv() returned 0: %s\n", strerror(errno));
        return DISPATCH_ABORT;
    }
    p->pkt_size = rc;

    /* FIXME */
    rc = pkt_async_write(tun_fd, p, send_compl, &rx_pool);
    if (rc == -1)
        return DISPATCH_ABORT;

    return DISPATCH_CONTINUE;
}

static int tun_recv(int fd, unsigned short flags, void *priv)
{
    struct pkt *p;
    int rc;
    /* FIXME */
    int sock_fd = (int)priv;

    p = pktqueue_dequeue(&tx_pool);
    if (!p) {
        fprintf(stderr, "RX packet pool exhausted\n");
        return DISPATCH_ABORT;
    }

    rc = read(fd, p->buff, p->buff_size);
    if (rc == -1) {
        fprintf(stderr, "recv() error: %s\n", strerror(errno));
        return DISPATCH_ABORT;
    }
    if (rc == 0) {
        fprintf(stderr, "recv() returned 0: %s\n", strerror(errno));
        return DISPATCH_ABORT;
    }
    p->pkt_size = rc;

    /* FIXME */
    rc = pkt_async_write(sock_fd, p, send_compl, &tx_pool);
    if (rc == -1)
        return DISPATCH_ABORT;

    return DISPATCH_CONTINUE;
}
int io_dispatch(int tunfd, int sockfd)
{
    struct dispatch d;
    struct event *pktcompl, *tun_ev, *sock_ev;

    init_pools(1500);

    setnonblock(tunfd);
    setnonblock(sockfd);

    dispatch_init(&d);
    pktcompl = pktcompl_event_create(&d);
    tun_ev = event_create(&d, tunfd, EVENT_READ, tun_recv, (void *)sockfd);
    sock_ev = event_create(&d, sockfd, EVENT_READ, sock_recv, (void *)tunfd);

    event_dispatch(&d);

    event_delete(&d, tun_ev);
    event_delete(&d, sock_ev);
    event_delete(&d, pktcompl);
    dispatch_cleanup(&d);

    return 0;
}

