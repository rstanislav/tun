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

    memset(&ee, 0, sizeof (ee));
    ee.data.ptr = e;

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

int event_control(struct dispatch *d, struct event *e, int ctl)
{
    struct epoll_event ee;
    int rc;
    unsigned short flags = e->flags;

    if (ctl == EVCTL_READ_STALL)
        flags &= ~EVENT_READ;
    if (ctl == EVCTL_READ_RESTART)
        flags |= EVENT_READ;
    if (ctl == EVCTL_WRITE_STALL)
        flags &= ~EVENT_WRITE;
    if (ctl == EVCTL_WRITE_RESTART)
        flags |= EVENT_WRITE;

    if (flags == e->flags)
        return 0;
    e->flags = flags;

    memset(&ee, 0, sizeof (ee));
    ee.data.ptr = e;

    if (e->flags & EVENT_READ)
        ee.events |= EPOLLIN;
    if (e->flags & EVENT_WRITE)
        ee.events |= EPOLLOUT;
    if (e->flags & EVENT_EDGE_TRIGGERED)
        ee.events |= EPOLLET;

    rc = epoll_ctl(d->epfd, EPOLL_CTL_MOD, e->fd, &ee);
    if (rc == -1) {
        fprintf(stderr, "epoll_ctl(MOD) failed: %s\n", strerror(errno));
        return -1;
    }

    return 0;
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
    LIST_FOREACH_SAFE(e, &d->handlers, link, te) {
        event_delete(d, e);
    }
}

#define DISPATCH_MAX_EVT 32

int event_dispatch(struct dispatch *d)
{
    struct epoll_event evts[DISPATCH_MAX_EVT];
    int rc;
    int i;
    int cont = DISPATCH_CONTINUE;

    do {
        rc = epoll_wait(d->epfd, evts, DISPATCH_MAX_EVT, -1);
        if (rc == -1) {
            if (errno == EINTR)
                continue;
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

            if (evts[i].events & EPOLLERR) {
                fprintf(stderr, "socket error.\n");
                return DISPATCH_ABORT;
            }

            cont = e->handler(e->fd, flags, e->priv);
            if (cont != DISPATCH_CONTINUE)
                break;
        }

    } while (cont == DISPATCH_CONTINUE);

    return cont;
}

