#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "pktqueue.h"

struct pktqueue pkt_pool;
struct pktqueue tx_queue;
struct pktqueue rx_queue;

void cleanup_queues(void)
{
    struct pkt *p;

    while ((p = pktqueue_dequeue(&pkt_pool)))
        pkt_free(p);
    while ((p = pktqueue_dequeue(&tx_queue)))
        pkt_free(p);
    while ((p = pktqueue_dequeue(&rx_queue)))
        pkt_free(p);
}

int init_queues(size_t buff_size, int max_buffs)
{
    int i;
    int ret = 0;

    pktqueue_init(&pkt_pool);
    pktqueue_init(&tx_queue);
    pktqueue_init(&rx_queue);

    for (i = 0; i < max_buffs; i++) {
        struct pkt *p = pkt_alloc(buff_size);

        if (!p) {
            ret = -ENOMEM;
            cleanup_queues();
            break;
        }

        pktqueue_enqueue(&pkt_pool, p);
    }

    return ret;
}

static int setnonblock(int fd)
{
    long fl;

    fl = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static void tun_ready(int fd, int evt)
{
    struct pkt *p;

    if ((evt & EPOLLOUT) &&  rx_queue.pkt_count) {
        p = pktqueue_dequeue(&rx_queue);
        write(fd, p->buff, p->pkt_size);
        p->pkt_size = 0;
        pktqueue_enqueue(&pkt_pool, p);
    }

    if ((evt & EPOLLIN) &&  pkt_pool.pkt_count) {
        p = pktqueue_dequeue(&pkt_pool);
        p->pkt_size = read(fd, p->buff, p->buff_size);
        pktqueue_enqueue(&tx_queue, p);
    }
}

static void sock_ready(int fd, int evts)
{
    struct pkt *p;

    if ((evts & EPOLLOUT) && tx_queue.pkt_count) {
        p = pktqueue_dequeue(&tx_queue);
        write(fd, p->buff, p->pkt_size);
        p->pkt_size = 0;
        pktqueue_enqueue(&pkt_pool, p);
    }

    if ((evts & EPOLLIN) &&  pkt_pool.pkt_count) {
        p = pktqueue_dequeue(&pkt_pool);
        p->pkt_size = read(fd, p->buff, p->buff_size);
        pktqueue_enqueue(&rx_queue, p);
    }
}

int work(int sockfd, int tunfd)
{
    int epollfd;
    struct epoll_event ev[2];
    int rc;

    setnonblock(sockfd);
    setnonblock(tunfd);

    epollfd = epoll_create(2);
    if (epollfd == -1) {
        fprintf(stderr, "Failed to create epoll instance: %s\n", strerror(errno));
        return -1;
    }

    ev[0].events = EPOLLIN | EPOLLOUT;
    ev[0].data.fd = sockfd;
    rc = epoll_ctl(epollfd, EPOLL_CTL_ADD, sockfd, &ev[0]);
    if (rc) {
        fprintf(stderr, "Failed to add socket to epoll instance: %s\n", strerror(errno));
        return -1;
    }

    ev[1].events = EPOLLIN | EPOLLOUT;
    ev[1].data.fd = tunfd;
    rc = epoll_ctl(epollfd, EPOLL_CTL_ADD, tunfd, &ev[1]);
    if (rc) {
        fprintf(stderr, "Failed to add tun dev to epoll instance: %s\n", strerror(errno));
        return -1;
    }

    while (1) {
        rc = epoll_wait(epollfd, ev, 2, -1);
        if (rc == -1) {
            fprintf(stderr, "epoll_wait(): %s\n", strerror(errno));
            return -1;
        }

        if (rc) {
            if (rc == 2 || ev[0].data.fd == tunfd)
                tun_ready(tunfd, ev[0].events);
            if (rc == 2 || ev[0].data.fd == sockfd)
                sock_ready(sockfd, ev[0].events);
        }
    }

    return 0;
}

