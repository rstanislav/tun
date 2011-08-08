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
