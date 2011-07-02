#ifndef PEER_H_
#define PEER_H_

#include <sys/queue.h>
#include <netinet/in.h>
#include <sys/types.h>

#include "iface.h"

enum peer_state
{
    PEER_STATE_UNKNOWN = 0,
    PEER_STATE_TRYCONNECT,
    PEER_STATE_CONNECTED
};

struct peer
{
    LIST_ENTRY(peer) link;

    int state;
    struct sockaddr_in addr;
    struct iface *iface;
    struct dispatch *dispatch;
};

struct peer *peer_lookup(struct sockaddr_in *addr);
struct peer *peer_create(struct dispatch *d, struct sockaddr_in *addr);
void peer_destroy(struct peer *p);
void peer_tryconnect(struct peer *p);

#endif /* PEER_H_ */
