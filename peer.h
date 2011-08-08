/*
 *  Copyright (c) 2011, Julian Pidancet <julian.pidancet@gmail.com>
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *  3. Neither the name of Julian Pidancet nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 *  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 *  COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 *  AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 *  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 *  OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *  SUCH DAMAGE.
 */

#ifndef PEER_H_
#define PEER_H_

#include <sys/queue.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

#include "iface.h"
#include "crypto.h"

#define HANDSHAKE_PROTO_ID 0
#define KEEPALIVE_PROTO_ID 1

#define PEER_LOG(_p, fmt, ...) \
    fprintf(stdout, "[%s:%d] "fmt"\n", \
            inet_ntoa((_p)->addr.sin_addr), \
            ntohs((_p)->addr.sin_port), \
            ##__VA_ARGS__)

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
    BF_KEY key;
    struct event *timer;
    int tx_count;
    int rx_count;
    int timeout;
    int abort_on_destroy;

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
    p->tx_count++;
    p->tx(pkt, &p->addr);
}

void handshake_init(struct peer *p);
void handshake_reset(struct peer *p);
int handshake_accept(struct peer *p, struct pkt *pkt);
int handshake_request(struct peer *p, struct pkt *pkt);
int handshake_connected(struct peer *p, struct pkt *pkt);

#endif /* PEER_H_ */
