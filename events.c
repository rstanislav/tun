#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/queue.h>

#include "events.h"

struct event *event_create(struct dispatch *d, int fd, unsigned short flags,
                           event_handler_t handler, void *priv)
{
    struct event *e;
    struct epoll_event ee;
    int rc;

    e = calloc(1, sizeof (*e));
    if (!e)
        return NULL;

    e->handler = handler;
    e->priv = priv;
    e->flags = flags;
    e->fd = fd;
    LIST_INSERT_HEAD(&d->handlers, e, link);

    ee.data.ptr = e;
    ee.events = 0;

    if (flags & EVENT_READ)
        ee.events |= EPOLLIN;
    if (flags & EVENT_WRITE)
        ee.events |= EPOLLOUT;
    if (flags & EVENT_EDGE_TRIGGERED)
        ee.events |= EPOLLET;

    rc = epoll_ctl(d->epfd, EPOLL_CTL_ADD, fd, &ee);
    if (rc == -1) {
        fprintf(stderr, "epoll_ctl(ADD) failed: %s\n", strerror(errno));
        LIST_REMOVE(e, link);
        free(e);
        return NULL;
    }

    return e;
}

void event_delete(struct dispatch *d, struct event *e)
{
    epoll_ctl(d->epfd, EPOLL_CTL_DEL, e->fd, (void *) -1);
    LIST_REMOVE(e, link);
    free(e);
}

int dispatch_init(struct dispatch *d)
{
    d->epfd = epoll_create(1024);
    if (d->epfd == -1) {
        fprintf(stderr, "epoll_create() failed: %s\n", strerror(errno));
        return -1;
    }

    LIST_INIT(&d->handlers);

    return 0;
}

void dispatch_cleanup(struct dispatch *d)
{
    struct event *e, *te;

    close(d->epfd);
    LIST_FOREACH_SAFE(e, te, &d->handlers, link) {
        event_delete(d, e);
    }
}

#define DISPATCH_MAX_EVT 32

int event_dispatch(struct dispatch *d, int timeout, int oneshot)
{
    struct epoll_event evts[DISPATCH_MAX_EVT];
    int rc;
    int i;
    int cont = DISPATCH_CONTINUE;

    do {
        rc = epoll_wait(d->epfd, evts, oneshot ? 1 : DISPATCH_MAX_EVT, timeout);
        if (rc == -1) {
            fprintf(stderr, "epoll_wait() failed: %s\n", strerror(errno));
            return DISPATCH_ABORT;
        }

        for (i = 0; i < rc; i++) {
            struct event *e = evts[i].data.ptr;
            short flags = 0;

            if (evts[i].events & EPOLLIN)
                flags |= EVENT_READ;
            if (evts[i].events & EPOLLOUT)
                flags |= EVENT_WRITE;

            cont = e->handler(e->fd, flags, e->priv);
            if (cont != DISPATCH_CONTINUE)
                break;
        }

    } while (!oneshot && (cont == DISPATCH_CONTINUE));

    return cont;
}

