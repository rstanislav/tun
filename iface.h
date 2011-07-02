#ifndef IFACE_H_
#define IFACE_H_

#include <netinet/in.h>
#include <sys/queue.h>

#include "events.h"
#include "pktqueue.h"

struct iface
{
    char name[IFNAMSIZ];
    int fd;
    struct sockaddr_in remote;

    struct pktqueue pool;
    struct pktqueue rx_queue;

    struct event *ev;
    struct dispatch *d;

    LIST_ENTRY(iface) link;
};

struct iface *iface_lookup(struct sockaddr_in *remote);
struct iface *iface_create(struct sockaddr_in *remote,
                           int pool_sz, size_t buff_sz);
void iface_destroy(struct iface *iface);
int iface_event_start(struct iface *iface, struct dispatch *d);
void iface_event_stop(struct iface *iface);

#endif /* IFACE_H_ */
