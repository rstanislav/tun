#ifndef PEER_H_
#define PEER_H_

#include <sys/queue.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <linux/if_ether.h>

#include "iface.h"
#include "crypto.h"

#define TUN_PROTO_ID 0

enum peer_state
{
    PEER_CONN_RESET = 0,
    PEER_CONN_REQUEST,
    PEER_CONN_ACCEPT,
    PEER_CONNECTED
};

static inline const char *peer_state_str(enum peer_state state)
{
    switch (state) {
        case PEER_CONN_RESET:
            return "PEER_CONN_RESET";
        case PEER_CONN_REQUEST:
            return "PEER_CONN_REQUEST";
        case PEER_CONN_ACCEPT:
            return "PEER_CONN_ACCEPT";
        case PEER_CONNECTED:
            return "PEER_CONNECTED";
    }

    return 0;
}

struct peer
{
    LIST_ENTRY(peer) link;

    int state;
    struct sockaddr_in addr;
    struct iface *iface;
    struct dispatch *dispatch;
    RSA *pubkey;

    tx_handler_t tx;
};

struct peer *peer_lookup(struct sockaddr_in *addr);
struct peer *peer_create(struct dispatch *d, struct sockaddr_in *addr,
                         tx_handler_t tx);
void peer_destroy(struct peer *p);
void peer_connect(struct peer *p);
void peer_receive(struct peer *p, struct pkt *pkt);

static inline void peer_send(struct peer *p, struct pkt *pkt)
{
    p->tx(pkt, &p->addr);
}

void handshake_init(struct peer *p);
void handshake_reset(struct peer *p);
int handshake_accept(struct peer *p, struct pkt *pkt);
int handshake_request(struct peer *p, struct pkt *pkt);
int handshake_connected(struct peer *p, struct pkt *pkt);

#endif /* PEER_H_ */
