#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "events.h"
#include "pktqueue.h"

#include "iface.h"

static void tx_complete(struct pkt *p, void *priv)
{
    struct iface *iface = priv;

    p->pkt_size = 0;
    pktqueue_enqueue(&iface->tx_pool, p);
    event_control(iface->d, iface->ev, EVCTL_READ_RESTART);
}

int iface_rx_schedule(struct iface *iface, struct pkt *p)
{
    int rc;

    pktqueue_enqueue(&iface->rx_queue, p);
    rc = event_control(iface->d, iface->ev, EVCTL_WRITE_RESTART);

    return rc;
}

static int iface_event_handler(int fd, unsigned short flags, void *priv)
{
    struct iface *iface = priv;
    struct pkt *p;
    int rc;

    if (flags & EVENT_READ) {
        p = pktqueue_dequeue(&iface->tx_pool);
        if (p) {
            rc = read(fd, p->buff, p->buff_size);
            if (rc <= 0)
                fprintf(stderr, "%s: read error.\n", iface->name);
            p->pkt_size = rc;
            pkt_set_compl(p, tx_complete, iface);
            iface->tx_handler(p, iface->tx_priv);
        } else {
            rc = event_control(iface->d, iface->ev, EVCTL_READ_STALL);
            if (rc)
                return DISPATCH_ABORT;
        }
    }

    if (flags & EVENT_WRITE) {
        p = pktqueue_dequeue(&iface->rx_queue);
        if (p) {
            rc = write(fd, p->buff, p->pkt_size);
            if (rc - p->pkt_size)
                fprintf(stderr, "%s: write error.\n", iface->name);

            pkt_complete(p);
        } else {
            rc = event_control(iface->d, iface->ev, EVCTL_WRITE_STALL);
            if (rc)
                return DISPATCH_ABORT;
        }
    }

    return DISPATCH_CONTINUE;
}

int iface_event_start(struct iface *iface, struct dispatch *d)
{
    iface->ev = event_create(d, iface->fd, EVENT_READ, iface_event_handler,
                             iface);
    if (!iface->ev)
        return -1;

    iface->d = d;

    return 0;
}

void iface_event_stop(struct iface *iface)
{
    event_delete(iface->d, iface->ev);
    iface->d = NULL;
}

static int setnonblock(int fd)
{
    long fl;

    fl = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static void set_mtu(struct ifreq *ifr, int mtu)
{
    int sock;
    int rc;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        fprintf(stderr, "socket(): %s\n", strerror(errno));
        return;
    }

    ifr->ifr_flags = 0;
    ifr->ifr_mtu = mtu;
    rc = ioctl(sock, SIOCSIFMTU, ifr);
    if (rc) {
        fprintf(stderr, "Failed to set MTU on %s: %s\n", ifr->ifr_name,
                strerror(errno));
    }

    close(sock);
}

struct iface *iface_create(int pool_sz, size_t mtu)
{
    struct iface *iface;
    struct ifreq ifr;
    int rc;
    int i;

    iface = calloc(1, sizeof (*iface));
    if (!iface)
        return NULL;

    iface->fd = open("/dev/net/tun", O_RDWR);
    if (iface->fd < 0) {
        fprintf(stderr, "Failed to open /dev/net/tun: %s\n", strerror(errno));
        free(iface);
        return NULL;
    }
    setnonblock(iface->fd);

    memset(&ifr, 0, sizeof (ifr));
    ifr.ifr_flags = IFF_TUN;
    strncpy(ifr.ifr_name, "tun%d", IFNAMSIZ);

    rc = ioctl(iface->fd, TUNSETIFF, &ifr);
    if (rc) {
        fprintf(stderr, "Failed to create tunnel interface: %s\n",
                strerror(errno));
        close(iface->fd);
        free(iface);
        return NULL;
    }

    strcpy(iface->name, ifr.ifr_name);

    set_mtu(&ifr, mtu);

    pktqueue_init(&iface->rx_queue);
    pktqueue_init(&iface->tx_pool);
    for (i = 0; i < pool_sz; i++) {
        struct pkt *p = pkt_alloc(mtu);

        if (!p)
            break;
        pktqueue_enqueue(&iface->tx_pool, p);
    }

    fprintf(stdout, "%s created.\n", iface->name);

    return iface;
}

void iface_destroy(struct iface *iface)
{
    struct pkt *p;

    fprintf(stdout, "destroy %s\n", iface->name);

    while ((p = pktqueue_dequeue(&iface->tx_pool))) {
        pkt_free(p);
    }
    while ((p = pktqueue_dequeue(&iface->rx_queue))) {
        pkt_free(p);
    }

    close(iface->fd);
    free(iface);
}
