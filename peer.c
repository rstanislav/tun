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

#include <stdio.h>
#include <unistd.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <sys/timerfd.h>

#include "pktqueue.h"
#include "events.h"
#include "iface.h"
#include "peer.h"

#ifndef IP_MTU
# define IP_MTU 14
#endif

#define PEER_RX_TIMEOUT 10

LIST_HEAD(, peer) peer_list = {NULL};

void peer_tx(struct pkt *pkt, void *priv)
{
    struct peer *p = priv;
#if 0
    struct tun_pi *hdr = (void *)pkt->buff;
    unsigned char *data = (void *)(hdr + 1);
    int len = pkt->pkt_size - sizeof (*hdr);

    /* tx filter */
#endif

    p->tx_count++;
    p->tx(pkt, &p->addr);
}

void peer_rx(struct peer *p, struct pkt *pkt)
{
#if 0
    struct tun_pi *hdr = (void *)pkt->buff;
    unsigned char *data = (void *)(hdr + 1);
    int len = pkt->pkt_size - sizeof (*hdr);

    /* rx filter */
#endif

    iface_rx_schedule(p->iface, pkt);
}

static struct pkt *tun_ctl_pkt(__u8 flags)
{
    struct pkt *pkt;
    struct tun_pi *hdr;
    struct tun_ctl *ctl;
    size_t len;

    len = sizeof (struct tun_pi) + sizeof (struct tun_ctl);

    pkt = pkt_alloc(len);
    if (!pkt)
        return NULL;
    hdr = (struct tun_pi *)pkt->buff;
    hdr->flags = 0;
    hdr->proto = htons(TUN_CTL_PROTO);
    pkt->pkt_size = len;

    ctl = (void *)(hdr + 1);
    ctl->ctl_flags = flags;

    return pkt;
}

static void peer_send_keepalive(struct peer *p)
{
    struct pkt *pkt;

    pkt = tun_ctl_pkt(0);
    if (!pkt)
        return;

    p->tx(pkt, &p->addr);
}

struct peer *peer_lookup(struct sockaddr_in *addr)
{
    struct peer *tmp, *p = NULL;

    LIST_FOREACH(tmp, &peer_list, link) {
        if (!memcmp(&tmp->addr, addr, sizeof (addr))) {
            p = tmp;
            break;
        }
    }

    return p;
}

static int timer_handler(int fd, unsigned short flags, void *priv)
{
    struct peer *p = priv;
    uint64_t expirations;
    int rc;

    (void)flags;

    rc = read(fd, &expirations, sizeof(expirations));
    if (rc != sizeof (expirations))
        PEER_LOG(p, "???");

    if (p->state == PEER_STATE_CLOSED)
        goto destroy;

    if (!p->tx_count) {
        peer_send_keepalive(p);
    }
    if (!p->rx_count) {
        if (--p->timeout == 0) {
            PEER_LOG(p, "No RX activity recorded for the past %d seconds."
                        " Destroying...",
                     PEER_RX_TIMEOUT);
destroy:
            if (p->abort_on_destroy)
                return DISPATCH_ABORT;
            else {
                peer_destroy(p);
                return DISPATCH_CONTINUE;
            }
        }
    } else {
        p->timeout = PEER_RX_TIMEOUT;
    }

    p->tx_count = p->rx_count = 0;

    return DISPATCH_CONTINUE;
}

static void peer_arm_timer(struct peer *p, int enable)
{
    struct itimerspec its = {{0, 0}, {0, 0}};
    struct itimerspec old;

    if (enable) {
        its.it_interval.tv_sec = 1;
        its.it_value.tv_sec = 1;
    }

    timerfd_settime(p->timer->fd, 0, &its, &old);
}

struct peer *peer_create(struct dispatch *d, struct sockaddr_in *addr,
                         tx_handler_t tx)
{
    struct peer *p;
    int timerfd;

    p = calloc(1, sizeof (*p));
    if (!p)
        return NULL;

    p->dispatch = d;
    p->state = PEER_STATE_INVALID;
    p->tx = tx;
    memcpy(&p->addr, addr, sizeof (*addr));
    LIST_INSERT_HEAD(&peer_list, p, link);
    timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (timerfd == -1) {
        peer_destroy(p);
        return NULL;
    }
    p->timer = event_create(p->dispatch, timerfd, EVENT_READ,
                            timer_handler, p);
    if (!p->timer) {
        peer_destroy(p);
        return NULL;
    }
    p->timeout = PEER_RX_TIMEOUT;

    return p;
}

void peer_destroy(struct peer *p)
{
    if (p->iface) {
        iface_event_stop(p->iface);
        iface_destroy(p->iface);
    }
    if (p->timer) {
        int fd = p->timer->fd;
        event_delete(p->dispatch, p->timer);
        close(fd);
    }
    LIST_REMOVE(p, link);
    free(p);
}

static int mtu_discover(struct sockaddr_in *addr)
{
    int sock;
    int mtu = ETH_DATA_LEN;
    int rc;
    socklen_t len = sizeof (mtu);

    /* HACK: To discover MTU, Create and connect back a socket to the host */
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return mtu;
    rc = connect(sock, (struct sockaddr *) addr, sizeof (*addr));
    if (rc) {
        fprintf(stderr, "%s: connect() failed: %s\n", __func__,
                strerror(errno));
        goto close;
    }

    rc = getsockopt(sock, IPPROTO_IP, IP_MTU, &mtu, &len);
    if (rc)
        fprintf(stderr, "Error Getting MTU: %s\n", strerror(errno));

close:
    close(sock);

    return mtu;
}

static int peer_iface_init(struct peer *p)
{
    int mtu;

    /*
     * Transport frame layout:
     *
     *                 <----------         Link MTU          ---------->
     *     <| Ethernet | IP | UDP | Tun PI |          Payload          |>
     *
     * Encapsulated frame layout:
     *                                    <| IP |         Data         |>
     *                                     <-------  Tunnel MTU ------->
     *
     * Tunnel MTU = Link MTU - (IP header size + UDP header size + Tun PI size)
     *            = Link MTU - 32
     */
    mtu = mtu_discover(&p->addr) - 32;

    p->iface = iface_create(1024, mtu);
    if (!p->iface) {
        fprintf(stderr, "Can't create interface.");
        return -1;
    }
    iface_event_start(p->iface, p->dispatch);
    iface_set_tx(p->iface, peer_tx, p);

    return 0;
}

static void peer_set_state(struct peer *p, int state)
{
    PEER_LOG(p, "%s -> %s", peer_state_str(p->state),
             peer_state_str(state));

    p->state = state;
}

void peer_connect(struct peer *p)
{
    struct pkt *pkt;

    /* Ship SYN */
    pkt = tun_ctl_pkt(TUN_CTL_SYN);
    peer_send(p, pkt);

    peer_set_state(p, PEER_STATE_CONNECTING);
    p->abort_on_destroy = 1;
}

void peer_listen(struct peer *p)
{
    peer_set_state(p, PEER_STATE_LISTENING);
}

void peer_ctl_rx(struct peer *p, struct pkt *pkt)
{
    struct tun_pi *hdr = (struct tun_pi *)pkt->buff;
    struct tun_ctl *ctl = (void *)(hdr + 1);
    size_t len = pkt->pkt_size - sizeof (*hdr);

    if (len < sizeof (*ctl)) {
        PEER_LOG(p, "Control packet too small.");
        return;
    }

    switch (p->state) {
    case PEER_STATE_INVALID:
        PEER_LOG(p, "Invalid peer state.");
        break;

    case PEER_STATE_LISTENING:
        if (ctl->ctl_flags & TUN_CTL_SYN) {
            struct pkt *ack = tun_ctl_pkt(TUN_CTL_ACK);

            peer_send(p, ack);
            goto set_connected;
        }
        break;

    case PEER_STATE_CONNECTING:
        if (ctl->ctl_flags & TUN_CTL_RST)
            goto set_closed;
        if (ctl->ctl_flags & TUN_CTL_ACK)
            goto set_connected;
        break;

    case PEER_STATE_CONNECTED:
        if (ctl->ctl_flags & TUN_CTL_RST)
            goto set_closed;
        break;

    default:
        PEER_LOG(p, "Bad state: %d", p->state);

    }

    return;
set_closed:
    peer_set_state(p, PEER_STATE_CLOSED);
    return;
set_connected:
    peer_arm_timer(p, 1);
    peer_set_state(p, PEER_STATE_CONNECTED);
    peer_iface_init(p);
}

void peer_receive(struct peer *p, struct pkt *pkt)
{
    struct tun_pi *hdr = (struct tun_pi *)pkt->buff;

    if (pkt->pkt_size < sizeof (*hdr)) {
        PEER_LOG(p, "Packet too small.");
        return;
    }

    switch (ntohs(hdr->proto)) {
    case ETH_P_IP:
        if (p->state == PEER_STATE_CONNECTED)
            peer_rx(p, pkt);
        else {
            PEER_LOG(p, "Protocol error: Not connected.");
        }
        break;
    case TUN_CTL_PROTO:
        peer_ctl_rx(p, pkt);
        break;
    default:
        PEER_LOG (p, "Unrecognized Protocol ID 0x%04x", ntohs(hdr->proto));
    }

    p->rx_count++;

    return;
}

