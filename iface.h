#ifndef IFACE_H_
#define IFACE_H_

#include <netinet/in.h>
#include <sys/queue.h>
#include <linux/if.h>

#include "events.h"
#include "pktqueue.h"

typedef void (*tx_handler_t)(struct pkt *, void *);

struct iface
{
    char name[IFNAMSIZ];
    int fd;

    struct pktqueue tx_pool;
    struct pktqueue rx_queue;

    tx_handler_t tx_handler;
    void *tx_priv;

    struct event *ev;
    struct dispatch *d;
};

int iface_rx_schedule(struct iface *iface, struct pkt *p);
struct iface *iface_create(int pool_sz, size_t mtu);
void iface_destroy(struct iface *iface);
int iface_event_start(struct iface *iface, struct dispatch *d);
void iface_event_stop(struct iface *iface);

static inline void iface_set_tx(struct iface *iface,
                                tx_handler_t tx_handler,
                                void *priv)
{
    iface->tx_handler = tx_handler;
    iface->tx_priv = priv;
}

#endif /* IFACE_H_ */
