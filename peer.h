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

#define TUN_CTL_PROTO 0

struct tun_ctl
{
#define TUN_CTL_SYN 0x01
#define TUN_CTL_ACK 0x02
#define TUN_CTL_RST 0x04
   __u8 ctl_flags;
};

#define PEER_LOG(_p, fmt, ...) \
    fprintf(stdout, "[%s:%d] "fmt"\n", \
            inet_ntoa((_p)->addr.sin_addr), \
            ntohs((_p)->addr.sin_port), \
            ##__VA_ARGS__)

enum peer_state
{
    PEER_STATE_INVALID = 0,
    PEER_STATE_LISTENING,
    PEER_STATE_CONNECTING,
    PEER_STATE_CONNECTED,
    PEER_STATE_CLOSED,
};

static inline const char *peer_state_str(enum peer_state state)
{
    switch (state) {
        case PEER_STATE_INVALID:
            return "PEER_STATE_INVALID";
        case PEER_STATE_LISTENING:
            return "PEER_STATE_LISTENING";
        case PEER_STATE_CONNECTING:
            return "PEER_STATE_CONNECTING";
        case PEER_STATE_CONNECTED:
            return "PEER_STATE_CONNECTED";
        case PEER_STATE_CLOSED:
            return "PEER_STATE_CLOSED";
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
void peer_listen(struct peer *p);

void peer_receive(struct peer *p, struct pkt *pkt);

static inline void peer_send(struct peer *p, struct pkt *pkt)
{
    p->tx_count++;
    p->tx(pkt, &p->addr);
}

#endif /* PEER_H_ */
