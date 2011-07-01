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
#include <sys/queue.h>

#include "events.h"
#include "pktqueue.h"

#include "iface.h"

static LIST_HEAD(,iface) iface_list = { NULL };

static int setnonblock(int fd)
{
    long fl;

    fl = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

struct iface *iface_lookup(struct sockaddr_in *remote)
{
    struct iface *iface, *ret = NULL;

    LIST_FOREACH(iface, &iface_list, link) {
        if (!memcmp(&iface->remote, remote, sizeof (*remote))) {
            ret = iface;
            break;
        }
    }

    return ret;
}

struct iface *iface_create(struct sockaddr_in *remote,
                           int pool_sz, size_t buff_sz)
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
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, "tun%d", IFNAMSIZ);

    rc = ioctl(iface->fd, TUNSETIFF, &ifr);
    if (rc) {
        fprintf(stderr, "Failed to create tunnel interface: %s\n", strerror(errno));
        close(iface->fd);
        free(iface);
        return NULL;
    }

    strcpy(iface->name, ifr.ifr_name);
    memcpy(&iface->remote, remote, sizeof (*remote));

    pktqueue_init(&iface->rx_queue);
    pktqueue_init(&iface->pool);
    for (i = 0; i < pool_sz; i++) {
        struct pkt *p = pkt_alloc(buff_sz);

        if (!p)
            break;
        pktqueue_enqueue(&iface->pool, p);
    }
    LIST_INSERT_HEAD(&iface_list, iface, link);

    fprintf(stdout, "%s created [%s:%d]\n", iface->name,
            inet_ntoa(remote->sin_addr), ntohs(remote->sin_port));

    return iface;
}

void iface_destroy(struct iface *iface)
{
    struct pkt *p;

    fprintf(stdout, "destroy %s\n", iface->name);

    while ((p = pktqueue_dequeue(&iface->pool))) {
        pkt_free(p);
    }
    while ((p = pktqueue_dequeue(&iface->rx_queue))) {
        pkt_free(p);
    }

    LIST_REMOVE(iface, link);
    close(iface->fd);
    free(iface);
}
