#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "pktqueue.h"
#include "events.h"

static struct pktqueue tx_pool;
static struct pktqueue tx_queue;
static struct dispatch evt_dispatch;
static struct event *socket_event;

#define PKT_POOL_SZ 1024
#define PKT_BUFF_SZ 1500

int socket_event_handler(int fd, unsigned short flags, void *priv)
{
    (void)priv;

    if (flags & EVENT_READ) {
        
    }

    if (flags & EVENT_WRITE) {

    }

    return DISPATCH_CONTINUE;
}

int io_dispatch(int listen, int sockfd)
{
    struct pkt *p;
    int rc;
    int i;

    pktqueue_init(&tx_pool);
    pktqueue_init(&tx_queue);
    for (i = 0; i < PKT_POOL_SZ; i++) {
        p = pkt_alloc(PKT_BUFF_SZ);
        if (!p)
            break;
        pktqueue_enqueue(&tx_pool, p);
    }

    rc = dispatch_init(&evt_dispatch);
    if (rc)
        goto cleanup;

    socket_event = event_create(&evt_dispatch, sockfd, EVENT_READ,
                                socket_event_handler, NULL);

cleanup:
    dispatch_cleanup(&evt_dispatch);
    while ((p = pktqueue_dequeue(&tx_pool))) {
        pkt_free(p);
    }
    while ((p = pktqueue_dequeue(&tx_queue))) {
        pkt_free(p);
    }
    return rc;
}

