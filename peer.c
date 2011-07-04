#include <stdio.h>
#include <unistd.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "pktqueue.h"
#include "events.h"
#include "iface.h"
#include "peer.h"

#ifndef IP_MTU
# define IP_MTU 14
#endif

LIST_HEAD(, peer) peer_list = {NULL};

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

struct peer *peer_create(struct dispatch *d, struct sockaddr_in *addr,
                         tx_handler_t tx)
{
    struct peer *p;

    p = calloc(1, sizeof (*p));
    if (!p)
        return NULL;

    p->dispatch = d;
    p->state = PEER_CONN_RESET;
    p->tx = tx;
    memcpy(&p->addr, addr, sizeof (*addr));
    LIST_INSERT_HEAD(&peer_list, p, link);

    return p;
}

void peer_destroy(struct peer *p)
{
    if (p->iface) {
        iface_event_stop(p->iface);
        iface_destroy(p->iface);
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
    iface_set_tx(p->iface, p->tx, &p->addr);

    return 0;
}

void peer_connect(struct peer *p)
{
    p->state = PEER_CONN_REQUEST;

    handshake_init(p);
}



static void peer_set_state(struct peer *p, int state)
{
    fprintf(stdout, "[%s:%d]: %s -> %s\n",
            inet_ntoa(p->addr.sin_addr),
            ntohs(p->addr.sin_port),
            peer_state_str(p->state),
            peer_state_str(state));

    p->state = state;
}

void peer_receive(struct peer *p, struct pkt *pkt)
{
    int rc;
    struct tun_pi *hdr = (struct tun_pi *)pkt->buff;

    if (pkt->pkt_size < sizeof (*hdr)) {
        fprintf(stderr, "Received packet too small.\n");
        return;
    }

    switch (ntohs(hdr->proto)) {
        case ETH_P_IP:
            if (p->state == PEER_CONNECTED)
                iface_rx_schedule(p->iface, pkt);
            else
                fprintf(stderr, "Received IP data but connection has not been "
                                "established yet\n");
            break;

        case 0x1337:
            switch (p->state) {
                case PEER_CONN_RESET:
                    peer_set_state(p, PEER_CONN_ACCEPT);
                case PEER_CONN_ACCEPT:
                    rc = handshake_accept(p, pkt);
                    if (rc == -1)
                        goto reset;
                    if (rc == 1)
                        goto connected;
                    break;

                case PEER_CONN_REQUEST:
                    rc = handshake_request(p, pkt);
                    if (rc == -1)
                        goto reset;
                    if (rc == 1)
                        goto connected;
                    break;

                case PEER_CONNECTED:
                    rc = handshake_connected(p, pkt);
                    if (rc == -1)
                        goto reset;
                    break;

                default:
                    fprintf(stderr, "Bad state %d\n", p->state);
            }

        default:
            fprintf(stderr, "Unrecognized Protocol 0x%04x\n",
                    ntohs(hdr->proto));
    }

    return;

reset:
    handshake_reset(p);
    peer_set_state(p, PEER_CONN_RESET);
    return;
connected:
    peer_set_state(p, PEER_CONNECTED);
    peer_iface_init(p);
}

